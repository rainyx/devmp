import capstone as cs
import capstone.x86 as cs_x86
from lief.PE import Binary
import struct as st
from utils import InstructionCollection, xor_sized, imatch
from universal import X86Reg
from entities import VMState


class VMPInstruction:

    def __init__(self):
        self.stack_delta = 0
        self.stack_reads = []
        self.stack_writes = []
        self.context_writes = []
        self.context_reads = []
        self.parameter_sizes = []
        self.parameters = []

    @classmethod
    def reduce_chunk(cls, inst):
        pass

    @classmethod
    def classify(cls, state: VMState, ic: InstructionCollection):

        out = cls()

        stack_instructions = [
            cs_x86.X86_INS_MOV,
            cs_x86.X86_INS_MOVZX,
            cs_x86.X86_INS_MOVSX,
            cs_x86.X86_INS_ADD,
            cs_x86.X86_INS_SUB,
            cs_x86.X86_INS_XOR,
            cs_x86.X86_INS_OR,
            cs_x86.X86_INS_AND,
        ]

        stack_op_read_target = None
        stack_op_write_target = None
        for inst_idx in range(len(ic)):
            inst = ic[inst_idx]
            for si in stack_instructions:
                if imatch(inst, si, cs_x86.X86_OP_REG, cs_x86.X86_OP_MEM):
                    if inst.operands[1].mem.base == state.vsp_reg.capstone:
                        stack_op_read_target = inst.operands[1].mem
                        break
                elif imatch(inst, si, cs_x86.X86_OP_MEM, cs_x86.X86_OP_REG):
                    if inst.operands[0].mem.base == state.vsp_reg.capstone:
                        stack_op_write_target = inst.operands[0].mem
                        break
                elif imatch(inst, cs_x86.X86_INS_PUSH, cs_x86.X86_OP_MEM):
                    if inst.operands[0].mem.base == state.vsp_reg.capstone:
                        stack_op_read_target = inst.operands[0].mem
                        break
                elif imatch(inst, cs_x86.X86_INS_POP, cs_x86.X86_OP_MEM):
                    if inst.operands[0].mem.base == state.vsp_reg.capstone:
                        stack_op_write_target = inst.operands[0].mem
                        break

            if stack_op_read_target is None and stack_op_write_target is None:
                pass
            else:
                def _process_mem_target(mem: cs_x86.X86OpMem):
                    return mem.index == out.stack_delta + mem.disp if cs_x86.X86_REG_INVALID else 0x10000000

                if stack_op_read_target:
                    out.stack_reads.append(_process_mem_target(stack_op_read_target))
                if stack_op_write_target:
                    out.stack_writes.append(_process_mem_target(stack_op_write_target))

            # Calculate stack delta
            if imatch(inst, cs_x86.X86_INS_ADD, cs_x86.X86_OP_REG, cs_x86.X86_OP_IMM) and \
                    inst.operands[0].reg == state.vsp_reg.capstone:
                out.stack_delta += inst.operands[1].imm
            elif imatch(inst, cs_x86.X86_INS_SUB, cs_x86.X86_OP_REG, cs_x86.X86_OP_IMM) and \
                    inst.operands[0].reg == state.vsp_reg.capstone:
                out.stack_delta -= inst.operands[1].imm
            elif imatch(inst, cs_x86.X86_INS_LEA, cs_x86.X86_OP_REG, cs_x86.X86_OP_MEM) and \
                    inst.operands[0].reg == state.vsp_reg.capstone and \
                    inst.operands[1].mem.base == state.vsp_reg.capstone and \
                    inst.operands[1].mem.index == cs_x86.X86_REG_INVALID:
                out.stack_delta += inst.operands[1].mem.disp
            elif imatch(inst, cs_x86.X86_INS_INC, cs_x86.X86_OP_REG) and \
                    inst.operands[0].reg == state.vsp_reg.capstone:
                out.stack_delta += 1
            elif imatch(inst, cs_x86.X86_INS_DEC, cs_x86.X86_OP_REG) and \
                    inst.operands[0].reg == state.vsp_reg.capstone:
                out.stack_delta -= 1
            else:
                vsp_written = False
                reg_uses, reg_defs = inst.regs_access()
                for reg in reg_defs:
                    if state.vsp_reg.is_equal_to_capstone(reg):
                        vsp_written = True
                        break
                if vsp_written:
                    out.stack_delta = 0x10000000
                    break

            # Track context operations
            def _is_ctx_mem_op(op: cs_x86.X86Op):
                if op.type == cs_x86.X86_OP_MEM and \
                        op.mem.base == cs_x86.X86_REG_RSP and \
                        op.mem.index != cs_x86.X86_REG_INVALID and \
                        op.mem.scale == 1 and \
                        op.mem.disp == 0:
                    return op.mem.index
                return None

            if inst.id == cs_x86.X86_INS_MOV:
                def _resolve_ctx_off(r):
                    print(inst)
                    j = inst_idx
                    while j >= 0:
                        if ic[j].mnemonic == 'loadc':
                            return ic[j].operands[1].imm
                        j -= 1
                    return None

                reg_w = _is_ctx_mem_op(inst.operands[0])
                print(inst_idx, reg_w)
                if reg_w is not None:
                    write_offset = _resolve_ctx_off(reg_w)
                    assert write_offset is not None
                    out.context_writes.append(write_offset)
                reg_r = _is_ctx_mem_op(inst.operands[1])
                if reg_r is not None:
                    read_offset = _resolve_ctx_off(reg_r)
                    assert read_offset is not None
                    out.context_reads.append(read_offset)

        # Extract parameters
        for inst in ic:
            if inst.mnemonic == 'loadc':
                out.parameter_sizes.append(inst.operands[0].size)
                out.parameters.append(inst.operands[1].imm)

        print(f"StackDelta: {out.stack_delta:x}, Parameters: {len(out.parameters)} "
              f"StackWrites: {len(out.stack_writes)} StackReads: {len(out.stack_reads)} "
              f"ContextWrites: {len(out.context_writes)} ContextReads: {len(out.context_reads)}")
