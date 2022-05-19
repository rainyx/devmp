from typing import NoReturn, Optional
import capstone as cs
import capstone.x86 as cs_x86
import unicorn as uc
import unicorn.x86_const as uc_x86
from lief.PE import Binary
import z3

from instructions import VMInstructions
from utils import InstructionCollection, LinkedList, xor_sized, imatch, unpack_int,\
    Mod2NInt, emulate_shared, get_shared_ks, get_shared_md
from universal import X86Reg
from entities import VMState, VMHandler, VIPDirection, VMDecryptionBlock, VMDecryptedInfo, VMBasicBlock, INVALID_RVA
from optimizers import VMInstructionsOptimizer
from execution import VMSymbolicExecutor, VMBranchAnalyzer


import struct as st


class VMTracer:

    def _get_inst(self, inst_str: str, address: int = 0) -> cs.CsInsn:
        ks = get_shared_ks()
        md = get_shared_md()
        code_bytes = bytes(ks.asm(inst_str.encode('utf-8'))[0])
        inst = next(md.disasm(code_bytes, address))
        return inst

    def _hook_invalid_mem(self, mu, access, address, size, value, user_data):
        print(f"Invalid memory access: {access} address: 0x{address:08x} sz: {size} val: 0x{value:x}")

    def _hook_mem(self, mu, access, address, size, value, user_data):
        # print(hex(mu.reg_read(self._current_state.vsp_reg.unicorn)))
        # if mu.reg_read(self._current_state.vsp_reg.unicorn) == 0xf000000000100090:
        if access == 16:
            value = st.unpack("<Q", mu.mem_read(address, 8))[0]
            print(f"Memory access: {access} address: 0x{address:08x} sz: {size} val: 0x{value:x}")
        else:
            before_value = st.unpack("<Q", mu.mem_read(address, 8))[0]
            print(f"Memory access: {access} address: 0x{address:08x} sz: {size} "
                  f"before_value: 0x{before_value:x} val: 0x{value:x}")

    def _format_eflags(self, eflags):
        flags = []
        if eflags & 0x1:
            flags.append("CF")
        if eflags & 0x4:
            flags.append("PF")
        if eflags & 0x10:
            flags.append("AF")
        if eflags & 0x40:
            flags.append("ZF")
        if eflags & 0x80:
            flags.append("SF")
        if eflags & 0x100:
            flags.append("TF")
        if eflags & 0x200:
            flags.append("IF")
        if eflags & 0x400:
            flags.append("DF")
        if eflags & 0x800:
            flags.append("OF")

        return "|".join(flags)

    def _hook_code2(self, _uc, address, size, user_data):
        # return
        if self._current_inst_idx < 2:
            self._current_inst_idx += 1
            return

        inst_idx = self._current_inst_idx - 2

        curr_handler_idx = self._last_handler_idx

        if self._last_handler_idx == -1:
            self._last_handler_idx = 0
        elif inst_idx > self._last_handler_end_i_idx:
            self._last_handler_idx += 1

        if curr_handler_idx != self._last_handler_idx:
            handler = self._current_bb[self._last_handler_idx]
            if self._last_handler_idx != 0:
                print_handler = self._current_bb[self._last_handler_idx - 1]

                v = _uc.reg_read(uc_x86.UC_X86_REG_EFLAGS)
                print(f"  ==== EFLAGS: 0x{v:08x} {self._format_eflags(v)}")
                print("  ==== VSP:")
                for i in range(0, 5):
                    addr = _uc.reg_read(self._current_state.vsp_reg.unicorn) + 8 * i
                    v = st.unpack("<Q", _uc.mem_read(addr, 8))[0]
                    print(f"  SP_{i}: [0x{addr:08x}] 0x{v:x}")
                # print("  ==== VCTX:")
                # for i in range(0, 30):
                #     addr = _uc.reg_read(X86Reg.RSP.unicorn) + 8 * i
                #     v = st.unpack("<Q", _uc.mem_read(addr, 8))[0]
                #     print(f"  CTX_{i}: [0x{addr:08x}] 0x{v:x}")

                print(f"Handler: {handler.virtualized_instruction}")

            self._last_handler_end_i_idx += len(handler.underlying_instructions)

        self._current_inst_idx += 1

        # inst = self._current_insts[self._current_inst_idx - 3]
        # print(f" [{self._current_inst_idx}] [{_uc.reg_read(uc_x86.UC_X86_REG_RIP):x}] {inst}")
        # for reg in [X86Reg.RSP, self._current_state.vsp_reg]:
        #     print(f"    {reg}: 0x{_uc.reg_read(reg.unicorn):x}")
        # reg_uses, reg_defs = inst.regs_access()
        # if reg_uses:
        #     print("    ==== reg uses:")
        #     for reg in reg_uses:
        #         u_reg = X86Reg.from_capstone(reg)
        #         print(f"    {u_reg}: 0x{_uc.reg_read(u_reg.unicorn):x}")
        #
        # if reg_defs:
        #     print("    ==== reg defs:")
        #     for reg in reg_defs:
        #         u_reg = X86Reg.from_capstone(reg)
        #         print(f"    {u_reg}")
        #
        # print("    ==== VSP:")
        # for i in range(-2, 2):
        #     v = st.unpack("<Q", _uc.mem_read(_uc.reg_read(self._current_state.vsp_reg.unicorn) + 8 * i, 8))[0]
        #     print(f"    SP_{i}: 0x{v:x}")
        #
        # print("    ==== EFLAGS:")
        # v = _uc.reg_read(uc_x86.UC_X86_REG_EFLAGS)
        # print(f"    EFLAGS: 0x{v:x}")
        # self._current_inst_idx += 1

    def _hook_code(self, uc, address, size, user_data):
        state = self._current_state

        def _is_mov_reg_mem(i):
            return imatch(i, cs_x86.X86_INS_MOV, cs.CS_OP_REG, cs.CS_OP_MEM)

        def _is_mov_mem_reg(i):
            return imatch(i, cs_x86.X86_INS_MOV, cs.CS_OP_MEM, cs.CS_OP_REG)

        def _is_mov_reg_imm(i):
            return imatch(i, [cs_x86.X86_INS_MOV, cs_x86.X86_INS_MOVABS], cs.CS_OP_REG, cs.CS_OP_IMM)

        def _is_mov_reg_reg(i):
            return imatch(i, cs_x86.X86_INS_MOV, cs.CS_OP_REG, cs.CS_OP_REG)

        def _is_pop_mem(i):
            return imatch(i, cs_x86.X86_INS_POP, cs.CS_OP_MEM)

        def _is_binary_reg_reg(i):
            return imatch(i, [cs_x86.X86_INS_ADD, cs_x86.X86_INS_OR, cs_x86.X86_INS_AND,
                          cs_x86.X86_INS_XOR, cs_x86.X86_INS_SHR], cs.CS_OP_REG, cs.CS_OP_REG)

        inst = self._current_insts[self._current_inst_idx]
        self._current_inst_idx += 1

        def _cast_bv(_bv, _sz: int):
            _target_bv_sz = _sz * 8
            if _bv.size() < _target_bv_sz:
                return z3.ZeroExt(_target_bv_sz - _bv.size(), _bv)
            elif _bv.size() > _target_bv_sz:
                return z3.Extract(_target_bv_sz - 1, 0, _bv)
            else:
                return _bv

        def _imm_value(_imm: int, _sz: int):
            _sz = 8
            if _imm not in self._imm_vals:
                _bv = z3.BitVec(f"imm_0x{_imm:x}", _sz * 8)
                self._imm_vals[_imm] = _bv
                self._val_imms[_bv] = _imm
            return _cast_bv(self._imm_vals[_imm], _sz)

        def _get_mem_address(_mem: cs_x86.X86OpMem):
            _address = 0
            if _mem.base != cs_x86.X86_REG_INVALID:
                _address = uc.reg_read(_mem.base)
            if _mem.index != cs_x86.X86_REG_INVALID:
                _address += uc.reg_read(_mem.index) * _mem.scale
            _address += _mem.disp
            return _address

        def _write_mem(_mem: cs_x86.X86OpMem, _bv):
            _address = _get_mem_address(_mem)
            self._mem_vals[_address] = _bv

        def _read_mem_address(_address: int, _sz: int):
            if _address not in self._mem_vals:
                _mem_bytes = uc.mem_read(_address, _sz)
                _val = unpack_int(_mem_bytes, _sz)
                # _bv = z3.BitVec(f"mem_0x{_val:x}", _sz * 8)
                # self._mem_vals[_address] = _bv
                self._mem_vals[_address] = _imm_value(_val, _sz)
            return _cast_bv(self._mem_vals[_address], _sz)

        def _read_mem(_mem: cs_x86.X86OpMem, _sz: int):
            _address = _get_mem_address(_mem)
            return _read_mem_address(_address, _sz)

        def _write_reg(_reg: int, _bv):
            _u_reg = X86Reg.from_capstone(_reg).extended
            self._reg_vals[_u_reg] = _bv

        def _read_reg(_reg: int, _sz: int):
            _u_reg = X86Reg.from_capstone(_reg).extended
            if _u_reg not in self._reg_vals:
                _val = uc.reg_read(_reg)
                # _bv = z3.BitVec(f"reg_0x{_val:x}", _sz * 8)
                # self._reg_vals[_u_reg] = _bv
                self._reg_vals[_u_reg] = _imm_value(_val, _sz)
            return _cast_bv(self._reg_vals[_u_reg], _sz)

        def _read_rsp(_sz: int):
            _address = uc.reg_read(uc_x86.UC_X86_REG_RSP)
            return _read_mem_address(_address, _sz)

        if _is_pop_mem(inst):
            _write_mem(inst.operands[0].mem, _read_rsp(inst.operands[0].size))
        elif _is_mov_reg_mem(inst):
            _write_reg(inst.operands[0].reg, _read_mem(inst.operands[1].mem, inst.operands[0].size))
        elif _is_mov_mem_reg(inst):
            _write_mem(inst.operands[0].mem, _read_reg(inst.operands[1].reg, inst.operands[0].size))
        elif _is_mov_reg_imm(inst):
            _write_reg(inst.operands[0].reg, _imm_value(inst.operands[1].imm, inst.operands[0].size))
        elif _is_mov_reg_reg(inst):
            _write_reg(inst.operands[0].reg, _read_reg(inst.operands[1].reg, inst.operands[0].size))
        elif _is_binary_reg_reg(inst):

            a = _read_reg(inst.operands[0].reg, inst.operands[0].size)
            b = _read_reg(inst.operands[1].reg, inst.operands[0].size)

            if a.size() != b.size():
                print(f"{inst.mnemonic} {b} asize: {a.size()}, bsize: {b.size()}")
            assert a.size() == b.size() and "Binary operation on different sizes"

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

            _write_reg(inst.operands[0].reg, c)

        elif imatch(inst, cs_x86.X86_INS_NOT, cs.CS_OP_REG):
            a = _read_reg(inst.operands[0].reg, inst.operands[0].size)
            _write_reg(inst.operands[0].reg, ~a)

    def __init__(self, binary: Binary):
        stack_base = 0xF000000000000000
        stack_size = 2 * 1024 * 1024
        rsp = stack_base + int(stack_size / 2)

        mu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64)

        mu.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED | uc.UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_invalid_mem)
        # mu.hook_add(uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE, self._hook_mem)
        mu.hook_add(uc.UC_HOOK_CODE, self._hook_code)
        # mu.hook_add(uc.UC_HOOK_INSN, self._hook_in, None, 1, 0, uc_x86.UC_X86_INS_OUT)

        # Setup stack
        mu.mem_map(stack_base, stack_size)
        mu.reg_write(uc_x86.UC_X86_REG_RSP, rsp)

        # Setup vmp section
        vmp_sec = None
        for sec in binary.sections:
            if sec.name == ".vmp0":
                vmp_sec = sec
                break
        vmp_sec_va = binary.optional_header.imagebase + vmp_sec.virtual_address
        mu.mem_map(vmp_sec_va, (vmp_sec.virtual_size // 0x100000 + 1) * 0x100000)
        mu.mem_write(vmp_sec_va, vmp_sec.content.tobytes())

        self._binary = binary
        self._mu = mu

        self._current_state = None
        self._current_insts = []
        self._current_inst_idx = 0
        self._current_bb = None
        self._last_handler_idx = -1
        self._last_handler_end_i_idx = 0
        self._last_vsp = 0
        self._vsp_base = 0
        self._reg_vals = {}
        self._mem_vals = {}
        self._imm_vals = {}
        self._val_imms = {}

    @property
    def emulator(self) -> uc.Uc:
        return self._mu

    @property
    def binary(self) -> Binary:
        return self._binary

    def trace(self, initial_state: VMState, vm_bb: VMBasicBlock):
        mu = self.emulator
        self._current_state = initial_state
        self._current_bb = vm_bb
        self._last_vsp = mu.reg_read(uc_x86.UC_X86_REG_RSP)

        image_base = self.binary.optional_header.imagebase

        init_code = f"mov {initial_state.vsp_reg.name}, RSP\n" \
                    f"sub RSP, 0x180\n" \
                    f"mov {initial_state.vip_reg.name}, 0x{initial_state.vip_rva + image_base:x}\n".encode('utf-8')
        insts = vm_bb.underlying_instructions
        insts.insert(0, self._get_inst(f"mov {initial_state.vsp_reg.name}, RSP"))
        insts.insert(1, self._get_inst(f"sub RSP, 0x180"))
        insts.append(self._get_inst(f"mov RAX, [{initial_state.vsp_reg.name}]"))

        self._current_insts = insts
        self._current_inst_idx = 0

        code_bytes = b"".join([i.bytes for i in insts])

        entry_va = image_base + vm_bb.entry_rva
        mu.mem_write(entry_va, code_bytes)
        mu.emu_start(entry_va, entry_va + len(code_bytes))

        val = mu.reg_read(uc_x86.UC_X86_REG_RAX)
        print("Trace", hex(val))

        aaa = self._reg_vals[X86Reg.EAX.extended]
        aaa = z3.simplify(aaa)
        print("simplify", aaa)

        def _find_cond(_expr):
            _decl = _expr.decl()
            if _decl.kind() == z3.Z3_OP_BOR:
                return _expr.arg(0)
            else:
                for _idx in range(_expr.num_args()):
                    _arg = _expr.arg(_idx)
                    _cond = _find_cond(_arg)
                    if _cond is not None:
                        return _cond

        def _get_all_constants(_expr, _vars):
            if z3.is_const(_expr):
                _vars.add(_expr)
            for _idx in range(_expr.num_args()):
                _arg = _expr.arg(_idx)
                _get_all_constants(_arg, _vars)

        def _sub_all_constants(_expr):
            constants = set()
            _get_all_constants(_expr, constants)
            for c in constants:
                if c in self._val_imms:
                    _expr = z3.substitute(_expr, (c, z3.BitVecVal(self._val_imms[c], c.size())))
            return _expr

        cond = _find_cond(aaa)
        if cond is not None:
            print("Cond", cond)
            cond_v = z3.BitVec('cond', cond.size())

            aaa = z3.substitute(aaa, (cond, cond_v))
            aaa = z3.substitute(aaa, (z3.simplify(~cond), ~cond_v))

            cond = _sub_all_constants(cond)
            cond = z3.simplify(cond)
            cond_not = z3.simplify(~cond)
            print("cond_v", cond, cond_not)

            aaa = _sub_all_constants(aaa)
            print("jump target", aaa)

            aaa_v1 = z3.simplify(z3.substitute(aaa, (cond_v, cond)))
            aaa_v2 = z3.simplify(z3.substitute(aaa, (cond_v, cond_not)))

            print("target_1", aaa_v1, "target_2", aaa_v2)
            # print("Sub", aaa)
        # ast = aaa.ast
        # print("ast", ast)
        # print(aaa.ast)
        # for i in ast.args():
        #     print(i)

        return val - image_base


def update_vip_direction(state: VMState, cursor: int, ic: InstructionCollection) -> NoReturn:
    def _forward_finder(i):
        # ----------------------------------------------------
        # add vip_reg, imm
        # ----------------------------------------------------
        if imatch(i, cs.x86.X86_INS_ADD, cs.x86.X86_OP_REG, cs.x86.X86_OP_IMM):
            return i.operands[0].reg == state.vip_reg.capstone and \
                   i.operands[1].imm > 0
        # ----------------------------------------------------
        # lea vip_reg, [vip_reg + imm]
        if imatch(i, cs.x86.X86_INS_LEA, cs.x86.X86_OP_REG, cs.CS_OP_MEM):
            return i.operands[0].reg == state.vip_reg.capstone and \
                   i.operands[1].mem.base == state.vip_reg.capstone and \
                   i.operands[1].mem.disp > 0 and \
                   i.operands[1].mem.scale == 1

    def _backward_finder(i):
        # ----------------------------------------------------
        # sub vip_reg, imm
        # ----------------------------------------------------
        if imatch(i, cs.x86.X86_INS_SUB, cs.x86.X86_OP_REG, cs.x86.X86_OP_IMM):
            return i.operands[0].reg == state.vip_reg.capstone and \
                   i.operands[1].imm > 0
        # ----------------------------------------------------
        # lea vip_reg, [vip_reg - imm]
        if imatch(i, cs.x86.X86_INS_LEA, cs.x86.X86_OP_REG, cs.CS_OP_MEM):
            return i.operands[0].reg == state.vip_reg.capstone and \
                   i.operands[1].mem.base == state.vip_reg.capstone and \
                   i.operands[1].mem.disp < 0 and \
                   i.operands[1].mem.scale == 1

    forward_idx = ic.next_index_by(cursor, _forward_finder)
    backward_idx = ic.next_index_by(cursor, _backward_finder)

    vip_dir = VIPDirection.UNSPECIFIED
    if forward_idx != -1:
        vip_dir = VIPDirection.FORWARD
    elif backward_idx != -1:
        vip_dir = VIPDirection.BACKWARD
    else:
        raise Exception("vip direction not determined")

    state.update_vip_direction(vip_dir)


def _decrypt(state: VMState, decryption_block: VMDecryptionBlock) -> VMDecryptedInfo:
    encrypted = state.read_vip(decryption_block.out_size)
    code_bytes = decryption_block.transforms.get_all_bytes()

    encrypted = xor_sized(encrypted, state.rolling_key, decryption_block.out_size)
    # print(f"  {encrypted_val:x}, {state.rolling_key:x}")

    out_reg_values = emulate_shared(code_bytes, {
        state.vrk_reg: state.rolling_key, decryption_block.def_reg: encrypted
    }, [decryption_block.def_reg, state.vrk_reg])

    decrypted = out_reg_values[decryption_block.def_reg]
    # print(f"decrypted_val:  {decrypted_val:x}")
    # update rolling key
    next_key = xor_sized(state.rolling_key, decrypted, decryption_block.out_size)
    state.update_rolling_key(next_key)

    d_info = VMDecryptedInfo(i_begin_index=decryption_block.i_begin_index, i_end_index=decryption_block.i_end_index,
                             def_reg=decryption_block.def_reg, out_size=decryption_block.out_size, value=decrypted)

    return d_info


def _next_decryption_block(state: VMState, cursor: int, ic: InstructionCollection) -> Optional[VMDecryptionBlock]:
    if state.vip_direction == 0:
        raise Exception("vip direction is not determined")

    def _def_finder(i) -> bool:
        if imatch(i, cs.x86.X86_INS_MOVZX, cs.x86.X86_OP_REG, cs.CS_OP_MEM):
            # ----------------------------------------------------
            # movzx reg, [vip_reg]
            # ----------------------------------------------------
            return state.vip_reg.is_equal_to_capstone(i.operands[1].mem.base)
        elif imatch(i, cs.x86.X86_INS_MOV, cs.x86.X86_OP_REG, cs.CS_OP_MEM):
            # ----------------------------------------------------
            # mov reg, [vip_reg]
            # ----------------------------------------------------
            return state.vip_reg.is_equal_to_capstone(i.operands[1].mem.base)
        else:
            return False

    def_idx, def_reg_i = ic.next_by(cursor, _def_finder)

    if def_idx == -1:
        return None

    def_reg = X86Reg.from_capstone(def_reg_i.operands[0].reg)
    out_size = def_reg_i.operands[1].size

    def _decryption_begin_finder(i) -> bool:
        # ----------------------------------------------------
        # xor vkr_reg, def_reg
        # ----------------------------------------------------
        return imatch(i, cs.x86.X86_INS_XOR, cs.x86.X86_OP_REG, cs.x86.X86_OP_REG) and \
               def_reg.is_equal_to_capstone(i.operands[0].reg) and \
               state.vrk_reg.is_equal_to_capstone(i.operands[1].reg)

    def _decryption_end_finder_1(i) -> bool:
        if imatch(i, cs.x86.X86_INS_XOR, cs.x86.X86_OP_REG, cs.x86.X86_OP_REG):
            # ----------------------------------------------------
            # xor def_reg, vrk_reg
            # ----------------------------------------------------
            return state.vrk_reg.is_equal_to_capstone(i.operands[0].reg)
        return False

    def _decryption_end_finder_2(i) -> bool:
        if imatch(i, cs.x86.X86_INS_XOR, cs.CS_OP_MEM, cs.x86.X86_OP_REG):
            # ----------------------------------------------------
            # push vrk_reg
            # * xor [rsp], def_reg
            # pop vrk_reg
            # ----------------------------------------------------
            return def_reg.is_equal_to_capstone(i.operands[1].reg) and \
                   i.operands[0].mem.base == cs_x86.X86_REG_RSP and \
                   i.operands[0].mem.disp == 0 and \
                   i.operands[0].mem.scale == 1 and \
                   i.operands[0].mem.index == cs_x86.X86_REG_INVALID
        return False

    begin_idx = ic.next_index_by(def_idx + 1, _decryption_begin_finder)
    barrier_idx = ic.next_index_by(begin_idx + 1, _def_finder)

    assert begin_idx != -1 and "decryption begin_idx not found"

    end_idx = ic.next_index_by(begin_idx + 1, _decryption_end_finder_2, barrier_idx)

    if end_idx != -1:
        def _pop_finder(i) -> bool:
            return imatch(i, cs.x86.X86_INS_POP, cs.x86.X86_OP_REG) and \
                    i.operands[0].reg == state.vrk_reg.capstone
        end_idx = ic.next_index_by(end_idx + 1, _pop_finder, barrier_idx)
    else:
        end_idx = ic.next_index_by(begin_idx + 1, _decryption_end_finder_1, barrier_idx)

    assert end_idx != -1 and "decryption end_idx not found"

    trans_ic, _ = ic.trace(def_reg.extended, begin_idx + 1, end_idx - 1)
    # print(f"Begin: {begin_idx} | End: {end_idx} | Barrier: {barrier_idx} | Def: {def_idx}")
    # for i in trans_ic:
    #     print(i)
    d_block = VMDecryptionBlock(i_begin_index=begin_idx, i_end_index=end_idx, def_reg=def_reg, out_size=out_size,
                                transforms=trans_ic)

    return d_block


def _next_decrypted(state: VMState, cursor: int, ic: InstructionCollection) -> Optional[VMDecryptedInfo]:
    d_blk = _next_decryption_block(state, cursor, ic)
    if d_blk is None:
        return None

    info = _decrypt(state, d_blk)
    return info


class VMEntryParser:

    @classmethod
    def _find_encrypted_vip(cls, ic: InstructionCollection) -> (int, int):
        # ----------------------------------------------------
        # push XXXXXX
        # ----------------------------------------------------
        assert imatch(ic[0], cs_x86.X86_INS_PUSH, cs.CS_OP_IMM) and "encrypted vip not found"
        return 0, ic[0].operands[0].imm

    @classmethod
    def _find_vip_reg(cls, cursor: int, ic: InstructionCollection) -> (int, X86Reg):
        def _finder(i):
            # ----------------------------------------------------
            # mov r64, [rsp + 0x90]
            # ----------------------------------------------------
            return imatch(i, cs_x86.X86_INS_MOV, cs.CS_OP_REG, cs.CS_OP_MEM) \
                   and i.operands[1].mem.base == cs_x86.X86_REG_RSP \
                   and i.operands[1].mem.scale == 1 \
                   and i.operands[1].mem.disp == 0x90

        idx, reg_i = ic.next_by(cursor, _finder)
        assert idx != -1 and "vip_reg not found"
        return idx, X86Reg.from_capstone(reg_i.operands[0].reg).extended

    @classmethod
    def _find_vsp_reg(cls, cursor: int, ic: InstructionCollection) -> (int, X86Reg):
        def _finder(i):
            # ----------------------------------------------------
            # mov r64, rsp
            # ----------------------------------------------------
            return imatch(i, cs_x86.X86_INS_MOV, cs.CS_OP_REG, cs.CS_OP_REG) \
                   and i.operands[1].reg == cs_x86.X86_REG_RSP

        idx, reg_i = ic.next_by(cursor, _finder)
        assert idx != -1 and "vsp_reg not found"
        return idx, X86Reg.from_capstone(reg_i.operands[0].reg).extended

    @classmethod
    def _find_vrk_reg(cls, cursor: int, vip_reg: X86Reg, ic: InstructionCollection) -> (int, X86Reg):
        def _finder(i):
            # ----------------------------------------------------
            # mov r64, vip_reg
            # ----------------------------------------------------
            return imatch(i, cs_x86.X86_INS_MOV, cs.CS_OP_REG, cs.CS_OP_REG) \
                   and i.operands[1].reg == vip_reg.capstone

        idx, reg_i = ic.next_by(cursor, _finder)
        assert idx != -1 and "vrk_reg not found"
        return idx, X86Reg.from_capstone(reg_i.operands[0].reg).extended

    @classmethod
    def _find_reloc_rva(cls, cursor: int, ic: InstructionCollection) -> (int, int):
        def _finder(i):
            # ----------------------------------------------------
            # lea r64, [rip - im]
            # ----------------------------------------------------
            return imatch(i, cs_x86.X86_INS_LEA, cs.CS_OP_REG, cs.CS_OP_MEM) \
                   and i.operands[1].mem.base == cs_x86.X86_REG_RIP

        idx, reg_i = ic.next_by(cursor, _finder)
        assert idx != -1 and "jmp_base not found"

        jmp_base_rva = reg_i.address

        return idx, jmp_base_rva

    """
    Return vip loaded address, e.g. 0x1400056f2
    """

    @classmethod
    def _decrypt_vip(cls, encrypted_vip: int, vip_reg: X86Reg,vip_i_idx, vsp_id_idx,
                     ic: InstructionCollection) -> int:
        sub_ic, depends = ic.trace(vip_reg, vip_i_idx + 1, vsp_id_idx - 1)
        assert len(sub_ic) and "can not decrypt vip"

        code_bytes = sub_ic.get_all_bytes()
        out_reg_values = emulate_shared(code_bytes, {vip_reg: encrypted_vip}, [vip_reg])

        return out_reg_values[vip_reg]

    @classmethod
    def parse(cls, binary: Binary, ic: InstructionCollection) -> (VMState, int):
        encrypted_vip_idx, encrypted_vip = cls._find_encrypted_vip(ic)
        vip_i_idx, vip_reg = cls._find_vip_reg(encrypted_vip_idx + 1, ic)
        vsp_i_idx, vsp_reg = cls._find_vsp_reg(vip_i_idx + 1, ic)
        vrk_i_idx, vrk_reg = cls._find_vrk_reg(vsp_i_idx + 1, vip_reg, ic)
        reloc_rva_i_idx, reloc_rva = cls._find_reloc_rva(vrk_i_idx + 1, ic)

        loaded_vip_va = cls._decrypt_vip(encrypted_vip, vip_reg, vip_i_idx, vsp_i_idx, ic)

        rolling_key = loaded_vip_va
        vip_rva = loaded_vip_va - binary.optional_header.imagebase

        state = VMState(binary=binary, vsp_reg=vsp_reg, vip_reg=vip_reg, vrk_reg=vrk_reg,
                        vip_rva=vip_rva, rolling_key=rolling_key, reloc_rva=reloc_rva)
        update_vip_direction(state, vsp_i_idx + 1, ic)

        # first_handler_off = next_parameter(state, vrk_i_idx + 1, ic)
        d_info = _next_decrypted(state, vrk_i_idx + 1, ic)

        first_handler_rva = Mod2NInt.normalize(reloc_rva + d_info.value, 32)
        return state, first_handler_rva


class VMSwapParser:

    class Result:
        def __init__(self, reloc_rva: int, i_end_index: int, prefix_ic: InstructionCollection):
            self.reloc_rva = reloc_rva
            self.i_end_index = i_end_index
            self.prefix_ic = prefix_ic

    @classmethod
    def _find_self_ref(cls, state: VMState, ic: InstructionCollection) -> Optional[int]:
        def _finder(i):
            # ----------------------------------------------------
            # lea r64, [$]
            # ----------------------------------------------------
            return imatch(i, cs_x86.X86_INS_LEA, cs.CS_OP_REG, cs.CS_OP_MEM) and \
                   i.operands[1].mem.disp == -7 and \
                   i.operands[1].mem.scale == 1 and \
                   i.operands[1].mem.base == cs_x86.X86_REG_RIP

        idx, def_i = ic.next_by(0, _finder)
        if idx == -1:
            return None
        else:
            return def_i.address

    @classmethod
    def try_parse(cls, state: VMState, ic: InstructionCollection) -> Optional[Result]:
        reloc_rva = cls._find_self_ref(state, ic)
        if reloc_rva is None:
            return None

        # ----------------------------------------------------
        # mov r64, [vsp]
        # ----------------------------------------------------
        read_vsp_i = ic[0]
        if imatch(read_vsp_i, cs_x86.X86_INS_MOV, cs.CS_OP_REG, cs.CS_OP_MEM):
            vip_from_reg = X86Reg.from_capstone(read_vsp_i.operands[0].reg)
            # ----------------------------------------------------
            # movabs r64, imm
            # ----------------------------------------------------
            idx_mutation_end = ic.next_index(1, cs_x86.X86_INS_MOVABS, cs.CS_OP_REG, cs.CS_OP_IMM)
            if idx_mutation_end == -1:
                return None

            vip_chain = LinkedList[X86Reg]()
            vip_chain.append(vip_from_reg)

            vsp_chain = LinkedList[X86Reg]()
            vsp_chain.append(state.vsp_reg)

            last_mapping = {
                vip_from_reg: vip_chain,
                state.vsp_reg: vsp_chain
            }  # type: dict[X86Reg, LinkedList[X86Reg]]
            mapping_chains = [vip_chain, vsp_chain]  # type: [LinkedList[X86Reg]]

            def _map(from_reg: X86Reg, to_reg: X86Reg):
                if from_reg not in last_mapping:
                    # junk mapping
                    return

                last_mapping[from_reg].append(to_reg)
                last_mapping[to_reg] = last_mapping[from_reg]

            prefix_end_idx = None
            for inst_idx in range(1, idx_mutation_end):
                inst = ic[inst_idx]

                if len(inst.operands) != 2 or inst.operands[0].size != 8:
                    continue

                changed = False
                if imatch(inst, cs_x86.X86_INS_MOV, cs.CS_OP_REG, cs.CS_OP_REG):
                    r1 = X86Reg.from_capstone(inst.operands[0].reg)
                    r2 = X86Reg.from_capstone(inst.operands[1].reg)
                    _map(r2, r1)
                    changed = True
                elif imatch(inst, cs_x86.X86_INS_XCHG, cs.CS_OP_REG, cs.CS_OP_REG):
                    r1 = X86Reg.from_capstone(inst.operands[0].reg)
                    r2 = X86Reg.from_capstone(inst.operands[1].reg)
                    _map(r2, r1)
                    _map(r1, r2)
                    changed = True
                if prefix_end_idx is None and changed:
                    prefix_end_idx = inst_idx - 1

            # for chain in mapping_chains:
            #     # print(f"Last: {reg}")
            #     print("new mapping chain: ")
            #     node = chain.head
            #     while node:
            #         print("  ", node.value)
            #         node = node.next

            new_vrk_reg_node = vip_chain.tail
            new_vip_reg_node = new_vrk_reg_node.prev
            new_vsp_reg_node = vsp_chain.tail

            prefix_ic = ic.range_of(1, prefix_end_idx)
            prefix_ic = VMInstructionsOptimizer.process(state, [], prefix_ic)
            # for i in prefix_ic:
            #     print(i)
            # print(f"After swap: VSP_REG: {new_vsp_reg_node}, VIP_REG: {new_vip_reg_node}, VRK_REG: {new_vrk_reg_node}")
            print(f"Before swap: VSP_REG: {state.vsp_reg} VIP_REG: {state.vip_reg} VRK_REG: {state.vrk_reg}")
            state.swap(new_vsp_reg=new_vsp_reg_node.value, new_vip_reg=new_vip_reg_node.value,
                       new_vrk_reg=new_vrk_reg_node.value)
            print(f"After swap: VSP_REG: {state.vsp_reg} VIP_REG: {state.vip_reg} VRK_REG: {state.vrk_reg}")
            update_vip_direction(state, idx_mutation_end + 1, ic)

            return cls.Result(reloc_rva=reloc_rva, i_end_index=idx_mutation_end, prefix_ic=prefix_ic)
        else:
            return None


class VMHandlerParser:

    @classmethod
    def _all_decryption_blocks(cls, state: VMState, ic: InstructionCollection) -> [VMDecryptionBlock]:
        d_blks = []
        cursor = 0
        while True:
            d_blk = _next_decryption_block(state=state, cursor=cursor, ic=ic)
            if d_blk:
                d_blks.append(d_blk)
                cursor = d_blk.i_end_index + 1
            else:
                break
        return d_blks

    @classmethod
    def try_parse(cls, state: VMState, handler_rva: int, initial_state: VMState,
                  vm_basic_block: VMBasicBlock, ic: InstructionCollection):

        swap = VMSwapParser.try_parse(state, ic)
        if swap:
            ic = ic.tail(swap.i_end_index + 1)

        d_blks = cls._all_decryption_blocks(state, ic)
        last_d_bkl = d_blks[-1]

        d_operand_infos = []
        operands = []
        operand_sizes = []

        # decrypt all operands
        for op_idx in range(len(d_blks) - 1):
            d_info = _decrypt(state, d_blks[op_idx])
            d_operand_infos.append(d_info)
            operands.append(d_info.value)
            operand_sizes.append(d_info.out_size)
            # print(f"{op_idx}, 0x{d_info.value:x}")

        # Discard calc_jmp_off routine
        ic = ic.head(last_d_bkl.i_begin_index)
        ic = VMInstructionsOptimizer.process(state, d_operand_infos, ic)
        if swap:
            ic = swap.prefix_ic + ic
        v_inst = VMInstructions.classify(state, operands, operand_sizes, ic)

        if v_inst.op == 'VJMP':
            # tracer = VMTracer(state.binary)
            # next_vip = tracer.trace(initial_state, vm_basic_block)
            branches = VMBranchAnalyzer.analyze(initial_state, vm_basic_block)
            print("Branches", branches)
            next_vip = branches[-1]
            next_rolling_key = state.binary.imagebase + next_vip
            state._vip_rva = next_vip
            state._rolling_key = next_rolling_key
            jmp_base = swap.reloc_rva
        else:
            jmp_base = handler_rva

        d_info = _decrypt(state, last_d_bkl)
        jmp_off = d_info.value
        next_rva = Mod2NInt.normalize(jmp_base + jmp_off, 32)

        handler = VMHandler(rva=ic[0].address, next_rva=next_rva, v_inst=v_inst, operands=operands, ic=ic)
        vm_basic_block.add_handler(handler)

        return handler
