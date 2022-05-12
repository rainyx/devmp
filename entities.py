import enum

from universal import X86Reg
from lief.PE import Binary
import struct as st

from utils import xor_sized, InstructionCollection, Mod2NInt, emulate_shared

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

    def read_vip(self, value_size: int) -> int:
        assert self.vip_direction != VIPDirection.UNSPECIFIED and "VIP direction not set"
        assert value_size in [1, 2, 4, 8] and "Invalid value_size"
        if self._vip_sec is None:
            self._vip_sec = self._binary.section_from_rva(self._vip_rva)

        value_off = self._vip_rva - self._vip_sec.virtual_address
        if self.vip_direction == VIPDirection.BACKWARD:
            value_off -= value_size

        value_bytes = self._vip_sec.content[value_off:value_off + value_size].tobytes()
        if value_size == 1:
            value = st.unpack('<B', value_bytes)[0]
        elif value_size == 2:
            value = st.unpack('<H', value_bytes)[0]
        elif value_size == 4:
            value = st.unpack('<I', value_bytes)[0]
        elif value_size == 8:
            value = st.unpack('<Q', value_bytes)[0]
        else:
            raise Exception("Incorrect val_sz: " + str(value_size))

        self._forward(value_size)
        return value

    def _forward(self, sz: int):
        assert self.vip_direction != VIPDirection.UNSPECIFIED and "VIP direction not set"

        if self.vip_direction == VIPDirection.FORWARD:
            self._vip_rva += sz
        elif self.vip_direction == VIPDirection.BACKWARD:
            self._vip_rva -= sz

    def __str__(self) -> str:
        return f"[VMS: {id(self)}:x] VSP_REG: {self.vsp_reg.name} VIP_REG: {self.vip_reg.name} " \
               f"VRK_REG: {self.vrk_reg.name} VRK: {self.rolling_key:x} VIP_RVA: {self.vip_rva}"


class VMEncryptedValue:
    def __init__(self, blk_start: int, blk_end: int, def_reg: X86Reg, encrypted_value: int, value_size: int,
                 transforms: InstructionCollection):
        self._blk_start = blk_start
        self._blk_end = blk_end
        self._def_reg = def_reg
        self._encrypted_value = encrypted_value
        self._value_size = value_size
        self._key = None
        self._next_key = None
        self._decrypted_value = None
        self._transforms = transforms

    @property
    def blk_start(self) -> int:
        return self._blk_start

    @property
    def blk_end(self) -> int:
        return self._blk_end

    @property
    def def_reg(self) -> X86Reg:
        return self._def_reg

    @property
    def encrypted_value(self) -> int:
        return self._encrypted_value

    @property
    def value_size(self) -> int:
        return self._value_size

    @property
    def decrypted_value(self) -> int:
        return self._decrypted_value

    @property
    def is_decrypted(self) -> bool:
        return self._decrypted_value is not None

    @property
    def key(self) -> int:
        return self._key

    @property
    def next_key(self) -> int:
        return self._next_key

    @property
    def transforms(self) -> InstructionCollection:
        return self._transforms

    def decrypt(self, state: VMState):
        """
        Decrypt value and update the rolling key fo vm state.
        :param state:
        :return:
        """
        # assert not self.is_decrypted and "Block already decrypted"
        self._key = state.rolling_key

        code_bytes = self.transforms.get_all_bytes()

        encrypted_val = xor_sized(self._encrypted_value, state.rolling_key, self._value_size)
        # print(f"  {encrypted_val:x}, {state.rolling_key:x}")

        out_reg_values = emulate_shared(code_bytes, {
            state.vrk_reg: state.rolling_key, self.def_reg: encrypted_val
        }, [self.def_reg, state.vrk_reg])

        self._decrypted_value = out_reg_values[self.def_reg]
        # print(f"decrypted_val:  {decrypted_val:x}")
        # update rolling key
        self._next_key = xor_sized(state.rolling_key, self._decrypted_value, self.value_size)
        state.update_rolling_key(self._next_key)

    def __str__(self):
        return f"[VEV: {id(self):x}] BLK_START: {self.blk_start} BLK_END: {self.blk_end} " \
               f"E_V: {self.encrypted_value:x} D_V: {self.decrypted_value:x} V_S: {self.value_size} " \
               f"KEY: {self.key:x} NEXT_KEY: {self.next_key:x}"


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


class VMHandler:

    def __init__(self, rva, parameters: list, v_inst: VMInstruction, ic: InstructionCollection):
        self._rva = rva
        self._parameters = parameters
        self._v_inst = v_inst
        self._ic = ic

    @property
    def next_rva(self):
        if not self.parameters:
            return INVALID_RVA

        next_off = self.parameters[-1].decrypted_value
        # ----------------------------------------------------
        # next_rva = handler_rva + next_handler_off (32bits)
        # ----------------------------------------------------
        next_rva = Mod2NInt.normalize(self.rva + next_off, 32)
        return next_rva

    @property
    def parameters(self) -> [VMEncryptedValue]:
        return self._parameters

    @property
    def rva(self) -> int:
        return self._rva

    @property
    def underlying_instructions(self) -> InstructionCollection:
        return self._ic

    @property
    def virtualized_instruction(self) -> VMInstruction:
        return self._v_inst

    def __str__(self):
        return f"[VH: {id(self):x}] RVA: {self.rva:x} PARAMETERS:{len(self.parameters)}" \
               f" NEXT_HANDLER: {self.next_rva:x}"


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
