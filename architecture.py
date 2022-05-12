import capstone as cs
import capstone.x86 as cs_x86
from lief.PE import Binary
import struct as st
from utils import InstructionCollection, xor_sized, imatch
from universal import X86Reg
from entities import VMState, VMInstruction


class VMOpcodeDescriptor:
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        return False

    def adjust_matching(self, state: VMState, v_inst: VMInstruction, variants: list):
        pass

    def reduce(self, state: VMState, v_inst: VMInstruction, identifier: str, variants: list = None) -> bool:
        if len(v_inst.parameters) != len(self.parameter_sizes):
            return False

        for i in range(len(self.parameter_sizes)):
            if self.parameter_sizes[i] != v_inst.parameter_sizes[i] and \
                    self.parameter_sizes[i] != VMInstruction.PANY:
                return False

        if variants is None:
            variants = []

        if '*' in identifier:
            possible_variants = {8, 4, 2, 1}
            abbrv_param_size = {8: 'Q', 4: 'D', 2: 'W', 1: 'B'}

            for v in possible_variants:
                concrete_identifier = identifier.replace('*', abbrv_param_size[v])
                if self.reduce(state, v_inst, concrete_identifier, variants + [v]):
                    return True

            return False

        if not self.match(state, v_inst, variants):
            return False

        v_inst.op = identifier
        self.adjust_matching(state, v_inst, variants)

    @classmethod
    def i_write_vsp(cls, state: VMState, inst: cs.CsInsn, offset: int, variant: int) -> bool:
        return (inst.id in (cs_x86.X86_INS_MOV, cs_x86.X86_INS_MOVZX)
                if variant == 1 else inst.id == cs_x86.X86_INS_MOV) and \
               inst.operands[0].type == cs.CS_OP_MEM and \
               inst.operands[0].mem.base == state.vsp_reg.capstone and \
               inst.operands[0].mem.index == cs_x86.X86_REG_INVALID and \
               inst.operands[0].mem.disp == offset

    @classmethod
    def i_read_vsp(cls, state: VMState, inst: cs.CsInsn, offset: int, variant: int) -> bool:
        return (inst.id in (cs_x86.X86_INS_MOV, cs_x86.X86_INS_MOVZX)
                if variant == 1 else inst.id == cs_x86.X86_INS_MOV) and \
               inst.operands[1].type == cs.CS_OP_MEM and \
               inst.operands[1].mem.base == state.vsp_reg.capstone and \
               inst.operands[1].mem.index == cs_x86.X86_REG_INVALID and \
               inst.operands[1].mem.disp == offset

    @classmethod
    def i_ref_vsp(cls, state: VMState, inst: cs.CsInsn, offset: int = 0) -> bool:
        if not offset and \
                inst.id == cs_x86.X86_INS_MOV and \
                inst.operands[1].type == cs.x86.X86_OP_REG and \
                inst.operands[1].reg == state.vsp_reg.capstone:
            return True

        return inst.id == cs_x86.X86_INS_LEA and \
               inst.operands[1].type == cs.CS_OP_MEM and \
               inst.operands[1].mem.base == state.vsp_reg.capstone and \
               inst.operands[1].mem.index == cs_x86.X86_REG_INVALID and \
               inst.operands[1].mem.disp == offset

    @classmethod
    def i_shift_vsp(cls, state: VMState, inst: cs.CsInsn, offset: int) -> bool:
        if abs(offset) & 1:
            return False

        if offset > 0:
            return inst.id == cs_x86.X86_INS_ADD and \
                   inst.operands[0].type == cs.x86.X86_OP_REG and \
                   inst.operands[0].reg == state.vsp_reg.capstone and \
                   inst.operands[1].type == cs.x86.X86_OP_IMM and \
                   inst.operands[1].imm == offset
        else:
            return inst.id == cs_x86.X86_INS_SUB and \
                   inst.operands[0].type == cs.x86.X86_OP_REG and \
                   inst.operands[0].reg == state.vsp_reg.capstone and \
                   inst.operands[1].type == cs.x86.X86_OP_IMM and \
                   inst.operands[1].imm == -offset

    @classmethod
    def i_loadc(cls, state: VMState, inst: cs.CsInsn) -> bool:
        return imatch(inst, [cs_x86.X86_INS_MOV, cs_x86.X86_INS_MOVABS], cs.CS_OP_REG, cs.CS_OP_IMM)

    @classmethod
    def i_write_ctx(cls, state: VMState, inst: cs.CsInsn, variant: int, disp: int = 0) -> bool:
        return (inst.id in (cs_x86.X86_INS_MOV, cs_x86.X86_INS_MOVZX)
                if variant == 1 else inst.id == cs_x86.X86_INS_MOV) and \
               inst.operands[0].type == cs.CS_OP_MEM and \
               inst.operands[0].mem.base == cs_x86.X86_REG_RSP and \
               inst.operands[0].mem.index != cs_x86.X86_REG_INVALID and \
               inst.operands[0].mem.scale == 1 and \
               inst.operands[0].mem.disp == disp and \
               (inst.operands[1].size <= 2 if variant == 1 else inst.operands[1].size == variant)

    @classmethod
    def i_read_ctx(cls, state: VMState, inst: cs.CsInsn, variant: int, disp: int = 0) -> bool:
        return (inst.id in (cs_x86.X86_INS_MOV, cs_x86.X86_INS_MOVZX)
                if variant == 1 else inst.id == cs_x86.X86_INS_MOV) and \
               inst.operands[1].type == cs.CS_OP_MEM and \
               inst.operands[1].mem.base == cs_x86.X86_REG_RSP and \
               inst.operands[1].mem.index != cs_x86.X86_REG_INVALID and \
               inst.operands[1].mem.scale == 1 and \
               inst.operands[1].mem.disp == disp and \
               (inst.operands[1].size <= 2 if variant == 1 else inst.operands[1].size == variant)

    @classmethod
    def i_save_vsp_flags(cls, state: VMState, inst0: cs.CsInsn, inst1: cs.CsInsn, offset: int = 0) -> bool:
        return inst0.id == cs_x86.X86_INS_PUSHFQ and \
               inst1.id == cs_x86.X86_INS_POP and \
               inst1.operands[0].type == cs.CS_OP_MEM and \
               inst1.operands[0].mem.base == state.vsp_reg.capstone and \
               inst1.operands[0].mem.index == cs_x86.X86_REG_INVALID and \
               inst1.operands[0].mem.disp == offset


class VUNKDescriptor(VMOpcodeDescriptor):
    """
    Unknown vmprotect instruction
    """


class VEXECDescriptor(VMOpcodeDescriptor):
    """
    Instructions executed as is
    """


class VEMITDescriptor(VMOpcodeDescriptor):
    """
    Emits the whole instruction stream to the raw x86-64 stream
    """


class VPOPVDescriptor(VMOpcodeDescriptor):
    """
    Pop from user stack into virtual machine context

    Pseudocode:
    ----------------------------------------------
    tmp         := [VSP]
    VSP         += *
    VCTX[pos]   := tmp
    ----------------------------------------------

    VPOPV*(u1 pos)
    """
    @property
    def parameter_sizes(self) -> []:
        return [1]

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic  # type: InstructionCollection
        ps = v_inst.parameter_sizes
        sz = 2 if var[0] == 1 else var[0]

        matched = len(ic) == 4 and \
                  self.i_read_vsp(state, ic[0], 0, var[0]) and \
                  self.i_shift_vsp(state, ic[1], sz) and \
                  self.i_loadc(state, ic[2]) and \
                  self.i_write_ctx(state, ic[3], var[0])
        if matched:
            return True

        matched = len(ic) == 4 and \
                  self.i_loadc(state, ic[0]) and \
                  self.i_read_vsp(state, ic[1], 0, var[0]) and \
                  self.i_shift_vsp(state, ic[2], sz) and \
                  self.i_write_ctx(state, ic[3], var[0])

        return matched


class VPOPDDescriptor(VMOpcodeDescriptor):
    """
    Pop from user stack into virtual machine context

    Pseudocode:
    ----------------------------------------------
    VSP         += *
    ----------------------------------------------

    VPOPD*()
    """
    @property
    def parameter_sizes(self) -> []:
        return [VMInstruction.PANY]

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        return len(ic) == 1 and self.i_shift_vsp(state, ic[0], +var[0])


class VPUSHCDescriptor(VMOpcodeDescriptor):
    """
    Push constant into user stack

    Pseudocode:
    ----------------------------------------------
    VSP			-=	*
    [VSP]		:=	const
    ----------------------------------------------

    VPUSHC*(u* const)
    """
    @property
    def parameter_sizes(self) -> []:
        return [VMInstruction.PANY]

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        sz = 2 if var[0] == 1 else var[0]
        return len(ic) == 3 and \
               self.i_loadc(state, ic[0]) and \
               self.i_shift_vsp(state, ic[1], -sz) and \
               self.i_write_vsp(state, ic[2], 0, var[0])


class VPUSHVDescriptor(VMOpcodeDescriptor):
    """
    Push into user stack from virtual machine context

    Pseudocode:
    ----------------------------------------------
    t0			:=	VCTX[pos]
    VSP			-=	*
    [VSP]		:=	t0
    ----------------------------------------------

    VPUSHV*(u8 pos)
    """
    @property
    def parameter_sizes(self) -> []:
        return [1]

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        sz = 2 if var[0] == 1 else var[0]
        return len(ic) == 4 and \
               self.i_loadc(state, ic[0]) and \
               self.i_read_ctx(state, ic[1], var[0]) and \
               self.i_shift_vsp(state, ic[2], -sz) and \
               self.i_write_vsp(state, ic[3], 0, var[0])


class VPUSHRDescriptor(VMOpcodeDescriptor):
    """
    Push a reference to current user stack pointer to the user stack

    Pseudocode:
    ----------------------------------------------
    t0			:=	VSP
    VSP			-=	*
    [VSP]*		:=	t0
    ----------------------------------------------

    VPUSHR()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        return len(ic) == 3 and \
               self.i_ref_vsp(state, ic[0], 0) and \
               self.i_shift_vsp(state, ic[1], -var[0]) and \
               self.i_write_vsp(state, ic[2], 0, var[0])


class VADDUDescriptor(VMOpcodeDescriptor):
    """
    Adds two integers from user stack and overwrites them with the results of the operation

    Pseudocode:
    ----------------------------------------------
    t0			:=	[VSP]
    t1			:=	[VSP+*]
    VSP			+= (*-8)
    tr			:=	t0 + t1
    tf			:=	EFLAGS
    [VSP+8]		:=	tr
    [VSP]		:=	tf
    ----------------------------------------------

    VADDU*()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        dt = 0 if var[0] == 8 else 1
        sz = 2 if var[0] == 1 else var[0]

        return len(ic) == (6 + dt) and \
               self.i_read_vsp(state, ic[0], 0, var[0]) and \
               self.i_read_vsp(state, ic[1], sz, var[0]) and \
               (dt == 0 or self.i_shift_vsp(state, ic[2], sz - 8)) and \
               ic[2 + dt].id == cs_x86.X86_INS_ADD and \
               self.i_write_vsp(state, ic[3 + dt], 8, var[0]) and \
               self.i_save_vsp_flags(state, ic[4 + dt], ic[5 + dt])


class VIMULUDescriptor(VMOpcodeDescriptor):
    """
    IMUL two integers from user stack and overwrite with the results

    Pseudocode:
    ----------------------------------------------
    *A			:=	[VSP+*]
    *D			:=	[VSP]
    VSP			-=	8
    IMUL(*D)
    [VSP+8]		:=	D
    [VSP+8+*]	:=	A
    [VSP]		:=	EFLAGS
    ----------------------------------------------

    VIMULU*()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        sz = 2 if var[0] == 1 else var[0]
        return len(ic) == 8 and \
               self.i_read_vsp(state, ic[0], sz, var[0]) and \
               X86Reg.RAX.is_equal_to_capstone(ic[0].operands[0].reg) and \
               self.i_read_vsp(state, ic[1], 0, var[0]) and \
               X86Reg.RDX.is_equal_to_capstone(ic[1].operands[0].reg) and \
               self.i_shift_vsp(state, ic[2], sz - 8) and \
               imatch(ic[3], cs_x86.X86_INS_IMUL, cs.CS_OP_REG) and \
               X86Reg.RDX.is_equal_to_capstone(ic[3].operands[0].reg) and \
               self.i_write_vsp(state, ic[4], +8, var[0]) and \
               X86Reg.RDX.is_equal_to_capstone(ic[4].operands[1].reg) and \
               self.i_write_vsp(state, ic[5], +8 + sz, var[0]) and \
               X86Reg.RAX.is_equal_to_capstone(ic[5].operands[1].reg) and \
               self.i_save_vsp_flags(state, ic[6], ic[7])


class VIDIVUDescriptor(VMOpcodeDescriptor):
    """
    IDIV two integers from user stack and overwrite with the results

    Pseudocode:
    ----------------------------------------------
    *A			:=	[VSP+*]
    *D			:=	[VSP]
    VSP			-=	8
    IDIV(*D)
    [VSP+8]		:=	D
    [VSP+8+*]	:=	A
    [VSP]		:=	EFLAGS
    ----------------------------------------------

    VIDIVU*()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        dt = 0 if var[0] == 8 else 1
        sz = 2 if var[0] == 1 else var[0]
        return len(ic) == (8 + dt) and \
               self.i_read_vsp(state, ic[0], sz, var[0]) and \
               X86Reg.RAX.is_equal_to_capstone(ic[0].operands[0].reg) and \
               self.i_read_vsp(state, ic[1], 0, var[0]) and \
               X86Reg.RDX.is_equal_to_capstone(ic[1].operands[0].reg) and \
               self.i_read_vsp(state, ic[2], sz * 2, var[0]) and \
               (not dt or self.i_shift_vsp(state, ic[3], sz - 8)) and \
               imatch(ic[3 + dt], cs_x86.X86_INS_IDIV, cs.CS_OP_REG) and \
               self.i_write_vsp(state, ic[4 + dt], +8, var[0]) and \
               X86Reg.RDX.is_equal_to_capstone(ic[4 + dt].operands[1].reg) and \
               self.i_write_vsp(state, ic[5 + dt], +8 + sz, var[0]) and \
               X86Reg.RAX.is_equal_to_capstone(ic[5 + dt].operands[1].reg) and \
               self.i_save_vsp_flags(state, ic[6 + dt], ic[7 + dt])


class VMULUDescriptor(VMOpcodeDescriptor):
    """
    MUL two integers from user stack and overwrite with the results

    Pseudocode:
    ----------------------------------------------
    *A			:=	[VSP+*]
    *D			:=	[VSP]
    VSP			-=	8
    MUL(*D)
    [VSP+8]		:=	D
    [VSP+8+*]	:=	A
    [VSP]		:=	EFLAGS
    ----------------------------------------------

    VMULU*()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        sz = 2 if var[0] == 1 else var[0]
        return len(ic) == 8 and \
               self.i_read_vsp(state, ic[0], sz, var[0]) and \
               X86Reg.RAX.is_equal_to_capstone(ic[0].operands[0].reg) and \
               self.i_read_vsp(state, ic[1], 0, var[0]) and \
               X86Reg.RDX.is_equal_to_capstone(ic[1].operands[0].reg) and \
               self.i_shift_vsp(state, ic[2], sz - 8) and \
               imatch(ic[3], cs_x86.X86_INS_MUL, cs.CS_OP_REG) and \
               X86Reg.RDX.is_equal_to_capstone(ic[3].operands[0].reg) and \
               self.i_write_vsp(state, ic[4], +8, var[0]) and \
               X86Reg.RDX.is_equal_to_capstone(ic[4].operands[1].reg) and \
               self.i_write_vsp(state, ic[5], +8 + sz, var[0]) and \
               X86Reg.RAX.is_equal_to_capstone(ic[5].operands[1].reg) and \
               self.i_save_vsp_flags(state, ic[6], ic[7])


class VDIVUDescriptor(VMOpcodeDescriptor):
    """
    DIV two integers from user stack and overwrite with the results

    Pseudocode:
    ----------------------------------------------
    *A			:=	[VSP+*]
    *D			:=	[VSP]
    VSP			-=	8
    DIV(*D)
    [VSP+8]		:=	D
    [VSP+8+*]	:=	A
    [VSP]		:=	EFLAGS
    ----------------------------------------------

    VDIVU*()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        dt = 0 if var[0] == 8 else 1
        sz = 2 if var[0] == 1 else var[0]
        return len(ic) == (8 + dt) and \
               self.i_read_vsp(state, ic[0], sz, var[0]) and \
               X86Reg.RAX.is_equal_to_capstone(ic[0].operands[0].reg) and \
               self.i_read_vsp(state, ic[1], 0, var[0]) and \
               X86Reg.RDX.is_equal_to_capstone(ic[1].operands[0].reg) and \
               self.i_read_vsp(state, ic[2], sz * 2, var[0]) and \
               (not dt or self.i_shift_vsp(state, ic[3], sz - 8)) and \
               imatch(ic[3 + dt], cs_x86.X86_INS_DIV, cs.CS_OP_REG) and \
               self.i_write_vsp(state, ic[4 + dt], +8, var[0]) and \
               X86Reg.RDX.is_equal_to_capstone(ic[4 + dt].operands[1].reg) and \
               self.i_write_vsp(state, ic[5 + dt], +8 + sz, var[0]) and \
               X86Reg.RAX.is_equal_to_capstone(ic[5 + dt].operands[1].reg) and \
               self.i_save_vsp_flags(state, ic[6 + dt], ic[7 + dt])


class VNORUDescriptor(VMOpcodeDescriptor):
    """
    NOR two integers from user stack and overwrites them with the results of the operation

    Pseudocode:
    ----------------------------------------------
    t0			:=	[VSP]
    t1			:=	[VSP+*]
    t1			:=	~t0
    t1			:=	~t1
    tr			:=	t0 | t1
    tf			:=	EFLAGS
    [VSP+8]		:=	tr
    [VSP]		:=	tf
    ----------------------------------------------

    VNORU*()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        dt = 0 if var[0] == 8 else 1
        sz = 2 if var[0] == 1 else var[0]

        return len(ic) == (8 + dt) and \
               self.i_read_vsp(state, ic[0], 0, var[0]) and \
               self.i_read_vsp(state, ic[1], sz, var[0]) and \
               (dt == 0 or self.i_shift_vsp(state, ic[2], sz - 8)) and \
               ic[2 + dt].id == cs_x86.X86_INS_NOT and \
               ic[3 + dt].id == cs_x86.X86_INS_NOT and \
               ic[4 + dt].id == cs_x86.X86_INS_OR and \
               self.i_write_vsp(state, ic[5 + dt], +8, var[0]) and \
               self.i_save_vsp_flags(state, ic[6 + dt], ic[7 + dt])


class VNANDUDescriptor(VMOpcodeDescriptor):
    """
    NAND two integers from user stack and overwrites them with the results of the operation

    Pseudocode:
    ----------------------------------------------
    t0			:=	[VSP]
    t1			:=	[VSP+*]
    t1			:=	~t0
    t1			:=	~t1
    tr			:=	t0 & t1
    tf			:=	EFLAGS
    [VSP+8]		:=	tr
    [VSP]		:=	tf
    ----------------------------------------------

    VNORU*()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        dt = 0 if var[0] == 8 else 1
        sz = 2 if var[0] == 1 else var[0]

        return len(ic) == (8 + dt) and \
               self.i_read_vsp(state, ic[0], 0, var[0]) and \
               self.i_read_vsp(state, ic[1], sz, var[0]) and \
               (dt == 0 or self.i_shift_vsp(state, ic[2], sz - 8)) and \
               ic[2 + dt].id == cs_x86.X86_INS_NOT and \
               ic[3 + dt].id == cs_x86.X86_INS_NOT and \
               ic[4 + dt].id == cs_x86.X86_INS_AND and \
               self.i_write_vsp(state, ic[5 + dt], +8, var[0]) and \
               self.i_save_vsp_flags(state, ic[6 + dt], ic[7 + dt])


class VSHRUDescriptor(VMOpcodeDescriptor):
    """
    Shifts ST[0]* right by ST[1]w and writes the results on top of the stack

    Pseudocode:
    ----------------------------------------------
    t0			:=	[VSP]
    t1			:=	[VSP+*]w
    VSP			-=  6
    tr			:=	t0 >> t1
    [VSP+8]		:=	tr
    [VSP]		:=	tf
    ----------------------------------------------

    VSHRU*()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        sz = 2 if var[0] == 1 else var[0]

        return len(ic) == 7 and \
               self.i_read_vsp(state, ic[0], 0, var[0]) and \
               self.i_read_vsp(state, ic[1], sz, 2) and \
               self.i_shift_vsp(state, ic[2], -6) and \
               ic[3].id == cs_x86.X86_INS_SHR and \
               self.i_write_vsp(state, ic[4], +8, var[0]) and \
               self.i_save_vsp_flags(state, ic[5], ic[6])


class VSHLUDescriptor(VMOpcodeDescriptor):
    """
    Shifts ST[0]* left by ST[1]w and writes the results on top of the stack

    Pseudocode:
    ----------------------------------------------
    t0			:=	[VSP]
    t1			:=	[VSP+*]w
    VSP			-=  6
    tr			:=	t0 << t1
    [VSP+8]		:=	tr
    [VSP]		:=	tf
    ----------------------------------------------

    VSHLU*()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        sz = 2 if var[0] == 1 else var[0]

        return len(ic) == 7 and \
               self.i_read_vsp(state, ic[0], 0, var[0]) and \
               self.i_read_vsp(state, ic[1], sz, 2) and \
               self.i_shift_vsp(state, ic[2], -6) and \
               ic[3].id == cs_x86.X86_INS_SHL and \
               self.i_write_vsp(state, ic[4], +8, var[0]) and \
               self.i_save_vsp_flags(state, ic[5], ic[6])


class VSHRDUDescriptor(VMOpcodeDescriptor):
    """
    SHRD and write the results on top of the stack

    Pseudocode:
    ----------------------------------------------
    t0			:=	[VSP]
    t1			:=	[VSP+*]
    t2			:=	[VSP+2*]b (but kinda treated like WORD because yea whatever LOL)
    VSP			+=  (*-6)
    SHRD(t0, t1, t2)
    [VSP+8]		:=	t0
    [VSP]		:=	tf
    ----------------------------------------------

    VSHRDU*()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        sz = 2 if var[0] == 1 else var[0]

        return len(ic) == 7 and \
               self.i_read_vsp(state, ic[0], 0, var[0]) and \
               self.i_read_vsp(state, ic[1], sz, var[0]) and \
               self.i_read_vsp(state, ic[2], sz * 2, 2) and \
               self.i_shift_vsp(state, ic[3], sz - 6) and \
               ic[4].id == cs_x86.X86_INS_SHRD and \
               self.i_write_vsp(state, ic[5], +8, var[0]) and \
               self.i_save_vsp_flags(state, ic[6], ic[7])


class VSHLDUDescriptor(VMOpcodeDescriptor):
    """
    SHLD and write the results on top of the stack

    Pseudocode:
    ----------------------------------------------
    t0			:=	[VSP]
    t1			:=	[VSP+*]
    t2			:=	[VSP+2*]b (but kinda treated like WORD because yea whatever LOL)
    VSP			+=  (*-6)
    SHLD(t0, t1, t2)
    [VSP+8]		:=	t0
    [VSP]		:=	tf
    ----------------------------------------------

    VSHLDU*()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        sz = 2 if var[0] == 1 else var[0]

        return len(ic) == 7 and \
               self.i_read_vsp(state, ic[0], 0, var[0]) and \
               self.i_read_vsp(state, ic[1], sz, var[0]) and \
               self.i_read_vsp(state, ic[2], sz * 2, 2) and \
               self.i_shift_vsp(state, ic[3], sz - 6) and \
               ic[4].id == cs_x86.X86_INS_SHLD and \
               self.i_write_vsp(state, ic[5], +8, var[0]) and \
               self.i_save_vsp_flags(state, ic[6], ic[7])


class VREADUDescriptor(VMOpcodeDescriptor):
    """
    Dereferences the top user stack entry and replaces it with the value

    Pseudocode:
    ----------------------------------------------
    t0			:=	[VSP]
    [VSP]		:=	[t0]
    ----------------------------------------------

    VREADU*()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        dt = 0 if var[0] == 8 else 1
        sz = 2 if var[0] == 1 else var[0]

        return len(ic) == 3 and \
               self.i_read_vsp(state, ic[0], 0, 8) and \
               ic[1].id in [cs_x86.X86_INS_MOV, cs_x86.X86_INS_MOVZX] and \
               ic[1].operands[1].type == cs_x86.X86_OP_MEM and \
               ic[1].operands[1].mem.index == cs_x86.X86_REG_INVALID and \
               ic[1].operands[1].mem.disp == 0 and \
               ic[1].operands[1].size == var[0] and \
               (dt == 0 or self.i_shift_vsp(state, ic[2], 8 - sz)) and \
               self.i_write_vsp(state, ic[2 + dt], 0, var[0])


class VWRITEUDescriptor(VMOpcodeDescriptor):
    """
    Pops a pointer from user stack, pops a u* from the stack and writes it into the pointer

    ----------------------------------------------
    t0			:=	[VSP]
    t1			:=	[VSP+8]
    VSP			+=	*
    [t0]		:=	t1
    ----------------------------------------------

    VWRITEU*()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        sz = 2 if var[0] == 1 else var[0]

        return len(ic) == 4 and \
               self.i_read_vsp(state, ic[0], 0, 8) and \
               self.i_read_vsp(state, ic[1], 8, var[0]) and \
               self.i_shift_vsp(state, ic[2], 8 + var[0]) and \
               ic[3].id == cs_x86.X86_INS_MOV and \
               ic[3].operands[0].type == cs_x86.X86_OP_MEM and \
               ic[3].operands[0].mem.index == cs_x86.X86_REG_INVALID and \
               ic[3].operands[0].mem.disp == 0


class VLOCKXCHGUDescriptor(VMOpcodeDescriptor):
    """
    LOCK XCHG the pointer on top of the stack with the value on top of that, discard the pointer

    Pseudocode:
    ----------------------------------------------
    t0			:=	[VSP]
    t1			:=	[VSP+8]
    VSP			+=	8
    LOCK XCHG [t0],	t1
    [VSP]		:=	t1
    ----------------------------------------------

    VLOCKXCHGU*()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        sz = 2 if var[0] == 1 else var[0]

        return len(ic) == 5 and \
               self.i_read_vsp(state, ic[0], 0, 8) and \
               self.i_read_vsp(state, ic[1], 8, var[0]) and \
               self.i_shift_vsp(state, ic[2], 8) and \
               ic[3].id == cs_x86.X86_INS_XCHG and \
               self.i_write_vsp(state, ic[4], 0, var[0])


class VCUPIDDescriptor(VMOpcodeDescriptor):
    """
    Pop CPUID branch from the top of the stack and push output

    Pseudocode:
    ----------------------------------------------
    br			:=  [VSP]
    CPUID(br)
    VSP			-=	0xC
    [VSP+0]		=	EDX
    [VSP+4]		=	ECX
    [VSP+8]		=	EBX
    [VSP+C]		=	EAX
    ----------------------------------------------

    VCPUID()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic

        return len(ic) == 7 and \
               self.i_read_vsp(state, ic[0], 0, 4) and \
               ic[1].id == cs_x86.X86_INS_CPUID and \
               self.i_shift_vsp(state, ic[2], -0xC) and \
               self.i_write_vsp(state, ic[3], 0xC, 4) and \
               self.i_write_vsp(state, ic[4], 0x8, 4) and \
               self.i_write_vsp(state, ic[5], 0x4, 4) and \
               self.i_write_vsp(state, ic[6], 0x0, 4)


class VCUPIDXDescriptor(VMOpcodeDescriptor):
    """
    Pop CPUID branch from the top of the stack and push output

    Pseudocode:
    ----------------------------------------------
    br			:=  [VSP]
    CPUID(br)
    VSP			-=	0xC
    [VSP+0]		=	EDX
    [VSP+4]		=	ECX
    [VSP+8]		=	EBX
    [VSP+C]		=	EAX
    ----------------------------------------------

    VCPUIDX()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        return len(ic) == 9 and \
               self.i_read_vsp(state, ic[0], 0, 4) and \
               ic[1].id == cs_x86.X86_INS_CPUID

    def adjust_matching(self, state: VMState, v_inst: VMInstruction, variants: list):
        v_inst.stack_delta = -0xC


class VRDTSCDescriptor(VMOpcodeDescriptor):
    """
    Execute RDTSC and push output

    Pseudocode:
    ----------------------------------------------
    RDTSC()
    VSP			-=	0x8
    [VSP+0]		=	EDX
    [VSP+8]		=	EAX
    ----------------------------------------------

    VRDTSC()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        return len(ic) == 4 and \
               ic[0].id == cs_x86.X86_INS_RDTSC and \
               self.i_shift_vsp(state, ic[1], -0x8) and \
               self.i_write_vsp(state, ic[2], 0, 4) and \
               self.i_write_vsp(state, ic[3], 4, 4)


class VSETVSPDescriptor(VMOpcodeDescriptor):
    """
    Pop new stack pointer value from top of the stack and replace VSP

    Pseudocode:
    ----------------------------------------------
    t0			:=  [VSP]
    VSP			=	t0		# Not visible in instruction stream beacuse it's below JA
    ----------------------------------------------

    VSETVSP()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        return len(ic) == 1 and \
               self.i_read_vsp(state, ic[0], 0, 8) and \
               ic[0].operands[0].type == cs.CS_OP_REG and \
               ic[0].operands[0].reg == state.vsp_reg.capstone


class VJMPDescriptor(VMOpcodeDescriptor):
    """
    Pop VIP from the top of the stack and continue execution

    Pseudocode:
    ----------------------------------------------
    VIP			=	[VSP]
    VSP			+=	0x8
    ----------------------------------------------

    VJMP()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        if len(ic) == 2:
            return ic[0].id == cs_x86.X86_INS_ADD and \
                   ic[0].operands[0].type == cs.CS_OP_REG and \
                   ic[0].operands[1].type == cs.CS_OP_IMM and \
                   ic[0].operands[1].imm == 8 and \
                   ic[1].id == cs_x86.X86_INS_LEA
        elif len(ic) == 3:
            return ic[0].id == cs_x86.X86_INS_MOV and \
                   ic[1].id == cs_x86.X86_INS_ADD and \
                   ic[1].operands[0].type == cs.CS_OP_REG and \
                   ic[1].operands[1].type == cs.CS_OP_IMM and \
                   ic[1].operands[1].imm == 8 and \
                   ic[2].id == cs_x86.X86_INS_LEA
        return False

    def adjust_matching(self, state: VMState, v_inst: VMInstruction, variants: list):
        v_inst.stack_reads.append(0)
        v_inst.stack_delta += 8


class VNOPDescriptor(VMOpcodeDescriptor):
    """
    Jumps a constant distance VIP, no effects

    Pseudocode:
    ----------------------------------------------
    VIP	+= distance
    ----------------------------------------------

    VNOP
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        return len(ic) == 1 and \
               ic[0].id == cs_x86.X86_INS_LEA


class VPUSHCR0Descriptor(VMOpcodeDescriptor):
    """
    Read control/debug register and push it

    Pseudocode:
    ----------------------------------------------
    t0          =   <reg>
    VSP			-=	0x8
    [VSP+0]		=	t0
    ----------------------------------------------

    VPUSH<special>()
    """
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        return len(ic) == 3 and \
               ic[0].id == cs_x86.X86_INS_MOV and \
               ic[0].operands[1].reg == cs_x86.X86_REG_CR0 and \
               self.i_shift_vsp(state, ic[1], -0x8) and \
               self.i_write_vsp(state, ic[2], 0, 8)


class VPUSHCR3Descriptor(VMOpcodeDescriptor):
    @property
    def parameter_sizes(self) -> []:
        return []

    def match(self, state: VMState, v_inst: VMInstruction, var: []) -> bool:
        ic = v_inst.ic
        return len(ic) == 3 and \
               ic[0].id == cs_x86.X86_INS_MOV and \
               ic[0].operands[1].reg == cs_x86.X86_REG_CR3 and \
               self.i_shift_vsp(state, ic[1], -0x8) and \
               self.i_write_vsp(state, ic[2], 0, 8)


class VMArchitecture:

    _opcodes = {
        # 'VUNK': VUNKDescriptor(),
        # 'VEMIT': VEMITDescriptor(),
        # 'VEXEC': VEXECDescriptor(),
        'VPOPV*': VPOPVDescriptor(),
        'VPOPD*': VPOPDDescriptor(),
        'VPUSHC*': VPUSHCDescriptor(),
        'VPUSHV*': VPUSHVDescriptor(),
        'VPUSHR*': VPUSHRDescriptor(),
        'VADDU*': VADDUDescriptor(),
        'VIMULU*': VIMULUDescriptor(),
        'VIDIVU*': VIDIVUDescriptor(),
        'VMULU*': VMULUDescriptor(),
        'VDIVU*': VDIVUDescriptor(),
        'VNORU*': VNORUDescriptor(),
        'VNANDU*': VNANDUDescriptor(),
        'VSHRU*': VSHRUDescriptor(),
        'VSHLU*': VSHLUDescriptor(),
        'VSHRDU*': VSHRDUDescriptor(),
        'VSHLDU*': VSHLDUDescriptor(),
        'VREADU*': VREADUDescriptor(),
        'VWRITEU*': VWRITEUDescriptor(),
        'VLOCKXCHGU*': VLOCKXCHGUDescriptor(),
        'VCUPID': VCUPIDDescriptor(),
        'VCUPIDX': VCUPIDXDescriptor(),
        'VRDTSC': VRDTSCDescriptor(),
        'VSETVSP': VSETVSPDescriptor(),
        'VJMP': VJMPDescriptor(),
        'VNOP': VNOPDescriptor(),
        'VPUSHCR0': VPUSHCR0Descriptor(),
        'VPUSHCR3': VPUSHCR3Descriptor()
    }

    @classmethod
    def reduce_chunk(cls, inst):
        pass

    @classmethod
    def classify(cls, state: VMState, ic: InstructionCollection):

        out = VMInstruction()
        out.op = "VUNK"
        out.ic = ic

        stack_instructions = (
            cs_x86.X86_INS_MOV,
            cs_x86.X86_INS_MOVZX,
            cs_x86.X86_INS_MOVSX,
            cs_x86.X86_INS_ADD,
            cs_x86.X86_INS_SUB,
            cs_x86.X86_INS_XOR,
            cs_x86.X86_INS_OR,
            cs_x86.X86_INS_AND,
        )

        for inst_idx in range(len(ic)):
            inst = ic[inst_idx]

            stack_op_read_target = None
            stack_op_write_target = None
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
                    return mem.index == out.stack_delta + mem.disp if cs_x86.X86_REG_INVALID \
                        else VMInstruction.UNKNOWN_DELTA

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
                    out.stack_delta = VMInstruction.UNKNOWN_DELTA
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
                    u_r = X86Reg.from_capstone(r)

                    def _finder(i):
                        return imatch(i, cs_x86.X86_INS_MOV, cs_x86.X86_OP_REG, cs_x86.X86_OP_IMM) and \
                               u_r.is_equal_to_capstone(i.operands[0].reg)

                    _, off_i = ic.prev_by(inst_idx, _finder)
                    return None if off_i is None else off_i.operands[1].imm

                reg_w = _is_ctx_mem_op(inst.operands[0])
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
            if imatch(inst, [cs_x86.X86_INS_MOV, cs_x86.X86_INS_MOVABS], cs_x86.X86_OP_REG, cs_x86.X86_OP_IMM):
                out.parameter_sizes.append(inst.operands[0].size)
                out.parameters.append(inst.operands[1].imm)

        for op_id, op_desc in cls._opcodes.items():
            if op_desc.reduce(state, out, op_id):
                break

        if out.op == "VUNK":
            out.op = "VEMIT"
            out.parameters = {0xCC}
            out.parameter_sizes = {1}

        print(f"StackDelta: {out.stack_delta:x},"
              f"Parameters: {len(out.parameters)} "
              f"ParameterSizes: {len(out.parameter_sizes)} "
              f"StackWrites: {len(out.stack_writes)} "
              f"StackReads: {len(out.stack_reads)} "
              f"ContextWrites: {len(out.context_writes)} "
              f"ContextReads: {len(out.context_reads)}")
        print(f"OP: {out.op}")
        return out
