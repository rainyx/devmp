from typing import NoReturn, Optional

import z3
import unicorn as uc
import unicorn.x86_const as uc_x86
import capstone as cs
import capstone.x86 as cs_x86

from entities import VMState, VMBasicBlock
from universal import X86Reg
from utils import imatch, unpack_int, str_to_cs_inst


_1MB = 1024 * 1024


class VMSymbolicExecutor:
    class State:
        def __init__(self, reg_vals: dict, mem_vals: dict, val_imms: dict):
            self._reg_vals = reg_vals
            self._mem_vals = mem_vals
            self._val_imms = val_imms

        @classmethod
        def get_all_constants(cls, expr, out: set) -> [z3.BitVecRef]:
            if z3.is_const(expr):
                out.add(expr)
            for idx in range(expr.num_args()):
                arg = expr.arg(idx)
                cls.get_all_constants(arg, out)

        def get_symbolic_register(self, reg: X86Reg) -> z3.BitVecRef:
            return self._reg_vals[reg.extended]

        def get_symbolic_memory(self, address: int) -> z3.BitVecRef:
            return self._mem_vals[address]

        def substitute_all_constants(self, expr: z3.ExprRef) -> z3.ExprRef:
            constants = set()
            self.get_all_constants(expr, constants)
            for c in constants:
                if c in self._val_imms:
                    expr = z3.substitute(expr, (c, z3.BitVecVal(self._val_imms[c], c.size())))
            return expr

    def __init__(self, state: VMState):
        self._state = state
        stack_base = 0xF000000000000000
        stack_size = 2 * _1MB
        rsp = stack_base + stack_size // 2

        self._mu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64)

        # Setup stack
        self._mu.mem_map(stack_base, stack_size)
        self._mu.reg_write(state.vsp_reg.capstone, rsp)
        self._mu.reg_write(uc_x86.UC_X86_REG_RSP, rsp - 0x180)

        self._reg_vals = {}  # type: {X86Reg: z3.BitVecRef}
        self._mem_vals = {}  # type: {int: z3.BitVecRef}
        self._imm_vals = {}  # type: {int: z3.BitVecRef}
        self._val_imms = {}  # type: {z3.BitVecRef: int}

    @staticmethod
    def _cast_bv(bv, sz: int) -> z3.BitVecRef:
        target_bv_sz = sz * 8
        if bv.size() < target_bv_sz:
            return z3.ZeroExt(target_bv_sz - bv.size(), bv)
        elif bv.size() > target_bv_sz:
            return z3.Extract(target_bv_sz - 1, 0, bv)
        else:
            return bv

    @staticmethod
    def _is_mov_reg_mem(i) -> bool:
        return imatch(i, cs_x86.X86_INS_MOV, cs.CS_OP_REG, cs.CS_OP_MEM)

    @staticmethod
    def _is_mov_mem_reg(i) -> bool:
        return imatch(i, cs_x86.X86_INS_MOV, cs.CS_OP_MEM, cs.CS_OP_REG)

    @staticmethod
    def _is_mov_reg_imm(i) -> bool:
        return imatch(i, [cs_x86.X86_INS_MOV, cs_x86.X86_INS_MOVABS], cs.CS_OP_REG, cs.CS_OP_IMM)

    @staticmethod
    def _is_mov_reg_reg(i) -> bool:
        return imatch(i, cs_x86.X86_INS_MOV, cs.CS_OP_REG, cs.CS_OP_REG)

    @staticmethod
    def _is_pop_mem(i) -> bool:
        return imatch(i, cs_x86.X86_INS_POP, cs.CS_OP_MEM)

    @staticmethod
    def _is_binary_reg_reg(i) -> bool:
        return imatch(i, [cs_x86.X86_INS_ADD, cs_x86.X86_INS_OR, cs_x86.X86_INS_AND,
                          cs_x86.X86_INS_XOR, cs_x86.X86_INS_SHR], cs.CS_OP_REG, cs.CS_OP_REG)

    def _get_imm_value(self, imm: int, sz: int) -> z3.BitVecRef:
        if imm not in self._imm_vals:
            bv = z3.BitVec(f"imm_0x{imm:x}", sz * 8)
            self._imm_vals[imm] = bv
            self._val_imms[bv] = imm
        return self._cast_bv(self._imm_vals[imm], sz)

    def _get_mem_address(self, mem: cs_x86.X86OpMem) -> int:
        address = 0
        if mem.base != cs_x86.X86_REG_INVALID:
            address = self.emulator.reg_read(mem.base)
        if mem.index != cs_x86.X86_REG_INVALID:
            address += self.emulator.reg_read(mem.index) * mem.scale
        address += mem.disp
        return address

    def _write_mem(self, mem: cs_x86.X86OpMem, bv) -> NoReturn:
        address = self._get_mem_address(mem)
        self._mem_vals[address] = bv

    def _read_mem_address(self, address: int, sz: int) -> z3.BitVecRef:
        if address not in self._mem_vals:
            mem_bytes = self.emulator.mem_read(address, sz)
            val = unpack_int(mem_bytes, sz)
            self._mem_vals[address] = self._get_imm_value(val, sz)
        return self._cast_bv(self._mem_vals[address], sz)

    def _read_mem(self, mem: cs_x86.X86OpMem, sz: int) -> z3.BitVecRef:
        address = self._get_mem_address(mem)
        return self._read_mem_address(address, sz)

    def _write_reg(self, reg: int, _bv) -> NoReturn:
        u_reg = X86Reg.from_capstone(reg).extended
        self._reg_vals[u_reg] = _bv

    def _read_reg(self, reg: int, sz: int) -> z3.BitVecRef:
        u_reg = X86Reg.from_capstone(reg).extended
        if u_reg not in self._reg_vals:
            val = self.emulator.reg_read(reg)
            self._reg_vals[u_reg] = self._get_imm_value(val, sz)
        return self._cast_bv(self._reg_vals[u_reg], sz)

    def _read_rsp(self, sz: int) -> z3.BitVecRef:
        address = self.emulator.reg_read(uc_x86.UC_X86_REG_RSP)
        return self._read_mem_address(address, sz)

    def _on_instruction(self, inst: cs.CsInsn) -> NoReturn:
        if self._is_pop_mem(inst):
            self._write_mem(inst.operands[0].mem, self._read_rsp(inst.operands[0].size))
        elif self._is_mov_reg_mem(inst):
            self._write_reg(inst.operands[0].reg, self._read_mem(inst.operands[1].mem, inst.operands[0].size))
        elif self._is_mov_mem_reg(inst):
            self._write_mem(inst.operands[0].mem, self._read_reg(inst.operands[1].reg, inst.operands[0].size))
        elif self._is_mov_reg_imm(inst):
            self._write_reg(inst.operands[0].reg, self._get_imm_value(inst.operands[1].imm, inst.operands[0].size))
        elif self._is_mov_reg_reg(inst):
            self._write_reg(inst.operands[0].reg, self._read_reg(inst.operands[1].reg, inst.operands[0].size))
        elif self._is_binary_reg_reg(inst):

            a = self._read_reg(inst.operands[0].reg, inst.operands[0].size)
            b = self._read_reg(inst.operands[1].reg, inst.operands[0].size)

            c = None
            if inst.id == cs_x86.X86_INS_ADD:
                c = a + b
            elif inst.id == cs_x86.X86_INS_OR:
                c = a | b
            elif inst.id == cs_x86.X86_INS_AND:
                c = a & b
            elif inst.id == cs_x86.X86_INS_XOR:
                c = a ^ b
            elif inst.id == cs_x86.X86_INS_SHR:
                c = a >> b

            if c is None:
                raise Exception(f"Unsupported binary instruction: {inst.mnemonic}")

            self._write_reg(inst.operands[0].reg, c)

        elif imatch(inst, cs_x86.X86_INS_NOT, cs.CS_OP_REG):
            a = self._read_reg(inst.operands[0].reg, inst.operands[0].size)
            self._write_reg(inst.operands[0].reg, ~a)

    @property
    def emulator(self) -> uc.Uc:
        return self._mu

    @property
    def state(self) -> VMState:
        return self._state

    def execute(self, insts: [cs.CsInsn]) -> State:
        mu = self.emulator

        code_bytes = b"".join([i.bytes for i in insts])

        code_base = 0x1000
        mu.mem_map(code_base, max((len(code_bytes) // _1MB + 1) * _1MB, _1MB))
        mu.mem_write(code_base, code_bytes)

        inst_idx = 0

        def _hook_code(*args):
            nonlocal inst_idx
            inst = insts[inst_idx]
            inst_idx += 1
            self._on_instruction(inst)
            return True

        mu.hook_add(uc.UC_HOOK_CODE, _hook_code)
        mu.emu_start(code_base, code_base + len(code_bytes))
        mu.hook_del(uc.UC_HOOK_CODE)

        return self.State(self._reg_vals, self._mem_vals, self._val_imms)


class VMBranchAnalyzer:

    @classmethod
    def _find_condition(cls, expr: z3.BitVecRef) -> Optional[z3.BitVecRef]:
        if expr.decl().kind() == z3.Z3_OP_BOR:
            return expr.arg(0)
        else:
            for _idx in range(expr.num_args()):
                cond = cls._find_condition(expr.arg(_idx))
                if cond is not None:
                    return cond
        return None

    @classmethod
    def analyze(cls, state: VMState, bb: VMBasicBlock) -> [int]:
        insts = bb.underlying_instructions
        insts.append(str_to_cs_inst(f"mov rax, [{state.vsp_reg.name}]"))

        executor = VMSymbolicExecutor(state)
        e_state = executor.execute(insts)

        dest_expr = e_state.get_symbolic_register(X86Reg.RAX)
        dest_expr = z3.simplify(dest_expr)

        cnd = cls._find_condition(dest_expr)

        if cnd is None:
            dest_expr = e_state.substitute_all_constants(dest_expr)
            return [z3.simplify(dest_expr).as_long() - state.binary.optional_header.imagebase]
        else:
            inv_cnd = z3.simplify(~cnd)
            cnd_val = z3.BitVec("cond_val", cnd.size())
            dest_expr = z3.substitute(dest_expr, (cnd, cnd_val))
            dest_expr = z3.substitute(dest_expr, (inv_cnd, ~cnd_val))
            dest_expr = e_state.substitute_all_constants(dest_expr)

            cnd = z3.simplify(e_state.substitute_all_constants(cnd))
            inv_cnd = ~cnd

            dest1 = z3.simplify(z3.substitute(dest_expr, (cnd_val, cnd)))
            dest2 = z3.simplify(z3.substitute(dest_expr, (cnd_val, inv_cnd)))

            return [dest1.as_long() - state.binary.optional_header.imagebase,
                    dest2.as_long() - state.binary.optional_header.imagebase]
