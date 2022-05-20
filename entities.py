import enum

from universal import X86Reg
from lief.PE import Binary
import struct as st

from utils import InstructionCollection, unpack_int

INVALID_RVA = -1


class VIPDirection(enum.Enum):
    UNSPECIFIED = 0
    FORWARD = 1
    BACKWARD = 2


class VMState:

    def __init__(self, binary: Binary, vsp_reg: X86Reg, vip_reg: X86Reg, vrk_reg: X86Reg, vip_rva: int,
                 rolling_key: int, reloc_rva, vip_direction: VIPDirection = VIPDirection.UNSPECIFIED):
        self._binary = binary

        self._vsp_reg = vsp_reg
        self._vip_reg = vip_reg
        self._vrk_reg = vrk_reg

        self._vip_rva = vip_rva
        self._rolling_key = rolling_key
        self._reloc_rva = reloc_rva
        self._vip_direction = vip_direction

        self._vip_sec = None

    @property
    def binary(self) -> Binary:
        return self._binary

    @property
    def vsp_reg(self) -> X86Reg:
        return self._vsp_reg

    @property
    def vip_reg(self) -> X86Reg:
        return self._vip_reg

    @property
    def vrk_reg(self) -> X86Reg:
        return self._vrk_reg

    @property
    def vip_rva(self) -> int:
        return self._vip_rva

    @property
    def vip_direction(self) -> VIPDirection:
        return self._vip_direction

    @property
    def rolling_key(self) -> int:
        return self._rolling_key

    @property
    def reloc_rva(self) -> int:
        return self._reloc_rva

    def set_reloc_rva(self, rva):
        self._reloc_rva = rva

    def duplicate(self):
        return self.__class__(binary=self.binary, vsp_reg=self.vsp_reg, vip_reg=self.vip_reg, vrk_reg=self.vrk_reg,
                              vip_rva=self.vip_rva, rolling_key=self.rolling_key, reloc_rva=self.reloc_rva,
                              vip_direction=self.vip_direction)

    def swap(self, new_vsp_reg: X86Reg, new_vip_reg: X86Reg, new_vrk_reg: X86Reg):
        self._vsp_reg = new_vsp_reg
        self._vip_reg = new_vip_reg
        self._vrk_reg = new_vrk_reg
        self._vip_sec = None

    def update_vip_direction(self, direction: VIPDirection):
        self._vip_direction = direction

    def update_rolling_key(self, new_key: int):
        self._rolling_key = new_key

    def read_vip(self, out_size: int) -> int:
        assert self.vip_direction != VIPDirection.UNSPECIFIED and "VIP direction not set"
        assert out_size in [1, 2, 4, 8] and "Invalid out_size"
        if self._vip_sec is None:
            self._vip_sec = self._binary.section_from_rva(self._vip_rva)

        data_off = self._vip_rva - self._vip_sec.virtual_address
        if self.vip_direction == VIPDirection.BACKWARD:
            data_off -= out_size

        data_bytes = self._vip_sec.content[data_off:data_off + out_size].tobytes()
        data = unpack_int(data_bytes, out_size)
        self._forward(out_size)
        return data

    def _forward(self, sz: int):
        assert self.vip_direction != VIPDirection.UNSPECIFIED and "VIP direction not set"

        if self.vip_direction == VIPDirection.FORWARD:
            self._vip_rva += sz
        elif self.vip_direction == VIPDirection.BACKWARD:
            self._vip_rva -= sz

    def __str__(self) -> str:
        return f"[VMS: {id(self)}:x] VSP_REG: {self.vsp_reg.name} VIP_REG: {self.vip_reg.name} " \
               f"VRK_REG: {self.vrk_reg.name} VRK: {self.rolling_key:x} VIP_RVA: {self.vip_rva}"


class VMDecryptionBlock:
    def __init__(self, i_begin_index: int, i_end_index: int, def_reg: X86Reg, out_size: int,
                 transforms: InstructionCollection):
        self._i_begin_index = i_begin_index
        self._i_end_index = i_end_index
        self._def_reg = def_reg
        self._out_size = out_size
        self._transforms = transforms

    @property
    def i_begin_index(self) -> int:
        return self._i_begin_index

    @property
    def i_end_index(self) -> int:
        return self._i_end_index

    @property
    def def_reg(self) -> X86Reg:
        return self._def_reg

    @property
    def out_size(self) -> int:
        return self._out_size

    @property
    def transforms(self) -> InstructionCollection:
        return self._transforms


class VMDecryptedInfo:
    def __init__(self, i_begin_index: int, i_end_index: int, def_reg: X86Reg, out_size: int, value: int):
        self._i_begin_index = i_begin_index
        self._i_end_index = i_end_index
        self._def_reg = def_reg
        self._out_size = out_size
        self._value = value

    @property
    def i_begin_index(self) -> int:
        return self._i_begin_index

    @property
    def i_end_index(self) -> int:
        return self._i_end_index

    @property
    def def_reg(self) -> X86Reg:
        return self._def_reg

    @property
    def out_size(self) -> int:
        return self._out_size

    @property
    def value(self) -> int:
        return self._value


class VMInstruction:
    UNKNOWN_DELTA = 0x10000000
    PANY = 0xAA

    def __init__(self):
        self.op = None
        self.stack_delta = 0
        self.stack_reads = []
        self.stack_writes = []
        self.context_writes = []
        self.context_reads = []
        self.parameter_sizes = []
        self.parameters = []

        self.ic = None

    def __str__(self):
        return f"[VMInst 0x{id(self):x}] OP: {self.op} OPS: {', '.join(map(str, self.parameters))} "


class VMOpcodes(enum.Enum):
    VUNK = "VUNK"

    VPOPVB = "VPOPVB"
    VPOPVW = "VPOPVW"
    VPOPVD = "VPOPVD"
    VPOPVQ = "VPOPVQ"

    VPOPDB = "VPOPDB"
    VPOPDW = "VPOPDW"
    VPOPDD = "VPOPDD"
    VPOPDQ = "VPOPDQ"

    VPUSHCB = "VPUSHCB"
    VPUSHCW = "VPUSHCW"
    VPUSHCD = "VPUSHCD"
    VPUSHCQ = "VPUSHCQ"

    VPUSHVB = "VPUSHVB"
    VPUSHVW = "VPUSHVW"
    VPUSHVD = "VPUSHVD"
    VPUSHVQ = "VPUSHVQ"

    VPUSHRB = "VPUSHRB"
    VPUSHRW = "VPUSHRW"
    VPUSHRD = "VPUSHRD"
    VPUSHQ = "VPUSHQ"

    VADDUB = "VADDUB"
    VADDUW = "VADDUW"
    VADDUD = "VADDUD"
    VADDUQ = "VADDUQ"

    VIMULUB = "VIMULUB"
    VIMULUW = "VIMULUW"
    VIMULUD = "VIMULUD"
    VIMULUQ = "VIMULUQ"

    VIDIVUB = "VIDIVUB"
    VIDIVUW = "VIDIVUW"
    VIDIVUD = "VIDIVUD"
    VIDIVUQ = "VIDIVUQ"

    VMULUB = "VMULUB"
    VMULUW = "VMULUW"
    VMULUD = "VMULUD"
    VMULUQ = "VMULUQ"

    VDIVUB = "VDIVUB"
    VDIVUW = "VDIVUW"
    VDIVUD = "VDIVUD"
    VDIVUQ = "VDIVUQ"

    VNORUB = "VNORUB"
    VNORUW = "VNORUW"
    VNORUD = "VNORUD"
    VNORUQ = "VNORUQ"

    VANDUB = "VANDUB"
    VANDUW = "VANDUW"
    VANDUD = "VANDUD"
    VANDUQ = "VANDUQ"

    VSHRUB = "VSHRUB"
    VSHRUW = "VSHRUW"
    VSHRUD = "VSHRUD"
    VSHRUQ = "VSHRUQ"

    VSHLUB = "VSHLUB"
    VSHLUW = "VSHLUW"
    VSHLUD = "VSHLUD"
    VSHLUQ = "VSHLUQ"

    VSHRDUB = "VSHRDUB"
    VSHRDUW = "VSHRDUW"
    VSHRDUD = "VSHRDUD"
    VSHRDUQ = "VSHRDUQ"

    VSHLDUB = "VSHLDUB"
    VSHLDUW = "VSHLDUW"
    VSHLDUD = "VSHLDUD"
    VSHLDUQ = "VSHLDUQ"

    VREADUB = "VREADUB"
    VREADUW = "VREADUW"
    VREADUD = "VREADUD"
    VREADUQ = "VREADUQ"

    VWRITEUB = "VWRITEUB"
    VWRITEUW = "VWRITEUW"
    VWRITEUD = "VWRITEUD"
    VWRITEUQ = "VWRITEUQ"

    VLOCKXCHGUB = "VLOCKXCHGUB"
    VLOCKXCHGUW = "VLOCKXCHGUW"
    VLOCKXCHGUD = "VLOCKXCHGUD"
    VLOCKXCHGUQ = "VLOCKXCHGUQ"

    VCPUID = "VCPUID"
    VCPUIDX = "VCPUIDX"

    VRDTSC = "VRDTSC"
    VSETVSP = "VSETVSP"
    VJMP = "VJMP"
    VNOP = "VNOP"
    VPUSHCR0 = "VPUSHCR0"
    VPUSHCR3 = "VPUSHCR3"


class VMHandler:

    def __init__(self, rva, next_rva: int, operands: [int], v_inst: VMInstruction, ic: InstructionCollection):
        self._rva = rva
        self._next_rva = next_rva
        self._operands = operands
        self._v_inst = v_inst
        self._ic = ic

    @property
    def operands(self) -> [int]:
        return self._operands

    @property
    def rva(self) -> int:
        return self._rva

    @property
    def next_rva(self) -> int:
        return self._next_rva

    @next_rva.setter
    def next_rva(self, new_rva: int):
        self._next_rva = new_rva

    @property
    def underlying_instructions(self) -> InstructionCollection:
        return self._ic

    @property
    def virtualized_instruction(self) -> VMInstruction:
        return self._v_inst

    def __str__(self):
        return f"[VH: {id(self):x}] RVA: {self.rva:x} PARAMETERS:{len(self.parameters)}" \
               f" NEXT_RVA: {self.next_rva:x}"


class VMBasicBlock:
    def __init__(self):
        self._handlers = []

    def add_handler(self, handler: VMHandler):
        self._handlers.append(handler)

    @property
    def handlers(self) -> [VMHandler]:
        return self._handlers

    def __str__(self):
        s = f"[VMB: {id(self):x}] HANDLERS: {len(self.handlers)}"
        if self.handlers:
            s += f" ENTRY: 0x{self.handlers[0].rva:x}"
        return s

    @property
    def entry_rva(self) -> int:
        return self._handlers[0].rva

    @property
    def code_bytes(self) -> bytes:
        code_bytes = b''
        for handler in self.handlers:
            code_bytes += handler.underlying_instructions.get_all_bytes()
        return code_bytes

    @property
    def underlying_instructions(self):
        insts = []
        for handler in self.handlers:
            insts += handler.underlying_instructions.to_list()
        return insts

    def __getitem__(self, item):
        return self._handlers[item]
