import capstone as cs
import capstone.x86 as cs_x86
import unicorn as uc
import unicorn.x86_const as uc_x86
import keystone as ks
import keystone.x86_const as ks_x86
from universal import X86Reg
from typing import TypeVar, Generic
import struct as st

T = TypeVar('T')


class LinkedList(Generic[T]):
    class Node:
        def __init__(self, value:T):
            self._value = value
            self._next = None
            self._prev = None

        @property
        def value(self) -> T:
            return self._value

        @value.setter
        def value(self, value:T):
            self._value = value

        @property
        def next(self) -> 'LinkedList[T].Node':
            return self._next

        @property
        def prev(self) -> 'LinkedList[T].Node':
            return self._prev

        def __str__(self):
            return f"[LinkedListNode: {id(self):x}] {self.value}"

    def __init__(self):
        self._head = None
        self._tail = None

    def append(self, value:T):
        node = self.Node(value)
        if self._head is None:
            self._head = node
            self._tail = node
        else:
            self._tail._next = node
            node._prev = self._tail
            self._tail = node

    @property
    def head(self) -> Node:
        return self._head

    @property
    def tail(self) -> Node:
        return self._tail


_shared_md = None
_shared_mu = None
_shared_ks = None


def get_shared_ks():
    global _shared_ks
    if _shared_ks is None:
        _shared_ks = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_64)
    return _shared_ks


def _create_emulator():
    stack_base = 0xF000000000000000
    stack_size = 2 * 1024 * 1024
    rsp = stack_base + int(stack_size / 2)

    mu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64)
    mu.mem_map(stack_base, stack_size)
    mu.reg_write(uc_x86.UC_X86_REG_RSP, rsp)

    def _hook_invalid_mem_access(mu, access, address, size, value, user_data):
        print(f"Invalid memory access: {access} {address:x} {size} {value:x}")

    mu.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED | uc.UC_HOOK_MEM_WRITE_UNMAPPED, _hook_invalid_mem_access)

    return mu


def emulate(mu: uc.Uc, code_bytes, initial_reg_values: {}, out_regs: [], code_base=None):
    if code_base is None:
        code_base = 0x1000

    code_size = max((len(code_bytes) // 1024 + 1) * 1024, 2 * 1024 * 1024)
    mu.mem_map(code_base, code_size)
    mu.mem_write(code_base, code_bytes)

    for reg, reg_value in initial_reg_values.items():
        mu.reg_write(reg.unicorn, initial_reg_values[reg])

    mu.emu_start(code_base, code_base + len(code_bytes))
    mu.mem_unmap(code_base, code_size)

    out_reg_values = {}
    for reg in out_regs:
        out_reg_values[reg] = mu.reg_read(reg.unicorn)
    return out_reg_values


def emulate_shared(code_bytes, initial_reg_values: {}, out_regs: [], code_base=None):
    global _shared_mu
    if _shared_mu is None:
        _shared_mu = _create_emulator()
    return emulate(_shared_mu, code_bytes, initial_reg_values, out_regs, code_base)


def get_shared_md():
    global _shared_md
    if _shared_md is None:
        _shared_md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        _shared_md.detail = True
    return _shared_md


def imatch(inst, inst_ids, *op_types):
    if type(inst_ids) is not list:
        inst_ids = [inst_ids]

    if inst.id not in inst_ids:
        return False
    if op_types:
        if len(inst.operands) < len(op_types):
            return False
        for i, op in enumerate(inst.operands):
            if op.type != op_types[i]:
                return False
    return True


def xor_sized(val, delta, size):
    if size == 1:
        return (val & 0xFFFFFFFFFFFFFF00) | ((val & 0xFF) ^ (delta & 0xFF))
    elif size == 2:
        return (val & 0xFFFFFFFFFFFF0000) | ((val & 0xFFFF) ^ (delta & 0xFFFF))
    elif size == 4:
        return (val & 0xFFFFFFFF00000000) | ((val & 0xFFFFFFFF) ^ (delta & 0xFFFFFFFF))
    elif size == 8:
        return val ^ delta
    else:
        raise Exception("invalid val_size")


class Mod2NInt:
    def __init__(self, value, n):
        self._mod_n = n
        self._ring = 2 ** n
        self._value = value
        self._normalize()

    @property
    def int_value(self):
        return self._value

    def _normalize(self):
        self._value = self._value % self._ring

    @classmethod
    def normalize(cls, val, mod_n):
        return cls(val, mod_n)._value

    def add(self, delta):
        return self.__class__(self._value + delta, self._mod_n)

    def sub(self, delta):
        return self.__class__(self._value - delta, self._mod_n)

    def mul(self, delta):
        return self.__class__(self._value * delta, self._mod_n)

    def div(self, delta):
        return self.__class__(self._value // delta, self._mod_n)

    def mod(self, delta):
        return self.__class__(self._value % delta, self._mod_n)

    def __add__(self, delta):
        return self.add(delta)

    def __sub__(self, delta):
        return self.sub(delta)

    def __mul__(self, delta):
        return self.mul(delta)

    def __div__(self, delta):
        return self.div(delta)

    def __mod__(self, delta):
        return self.mod(delta)

    def __eq__(self, other):
        return self._value == int(other)

    def __le__(self, other):
        return self._value <= int(other)

    def __lt__(self, other):
        return self._value < int(other)

    def __hash__(self):
        return hash(self._value)

    def __int__(self):
        return self._value

    def __format__(self, format_spec):
        return format(self._value, format_spec)


class InstructionCollection:
    def __init__(self, insts: []):
        self._insts = insts

    def prev(self, from_idx, inst_id, *op_types):
        idx = min(from_idx, len(self._insts) - 1)
        while idx >= 0:
            inst = self._insts[idx]
            if imatch(inst, inst_id, *op_types):
                return idx, inst
            idx -= 1
        return -1, None

    def prev_idx(self, from_idx, inst_id, *op_types):
        idx, _ = self.prev(from_idx, inst_id, *op_types)
        return idx

    def prev_by(self, from_idx, finder):
        idx = min(from_idx, len(self._insts) - 1)
        while idx >= 0:
            inst = self._insts[idx]
            if finder(inst):
                return idx, inst
            idx -= 1
        return -1, None

    def prev_index_by(self, from_idx, finder):
        idx, _ = self.prev_by(from_idx, finder)
        return idx

    def next(self, from_idx, inst_id, *op_types):
        idx = max(0, from_idx)
        while idx < len(self._insts):
            inst = self._insts[idx]
            if imatch(inst, inst_id, *op_types):
                return idx, inst
            idx += 1
        return -1, None

    def next_index(self, from_idx, inst_id, *op_types):
        idx, _ = self.next(from_idx, inst_id, *op_types)
        return idx

    def next_by(self, from_idx, finder, barrier_idx=-1):
        idx = max(0, from_idx)
        if barrier_idx == -1:
            barrier_idx = len(self._insts)
        while idx < barrier_idx:
            inst = self._insts[idx]
            if finder(inst):
                return idx, inst
            idx += 1
        return -1, None

    def next_index_by(self, from_idx, finder, barrier_idx=-1):
        idx, _ = self.next_by(from_idx, finder, barrier_idx)
        return idx

    def get_bytes(self, from_idx, to_idx):
        inst_bytes = b""
        for inst in self._insts[from_idx:to_idx + 1]:
            inst_bytes += inst.bytes
        return inst_bytes

    def get_all_bytes(self):
        return self.get_bytes(0, len(self._insts) - 1)

    def trace(self, regs, from_idx, to_idx):
        if type(regs) is not list:
            regs = [regs]
        depends_regs = set([r.extended for r in regs])
        sub_insts = []

        for inst in reversed(self._insts[from_idx:to_idx + 1]):
            write = False
            use_regs, def_regs = inst.regs_access()

            for r in def_regs:
                if X86Reg.from_capstone(r).extended in depends_regs:
                    write = True
                    break

            if write:
                for r in use_regs:
                    depends_regs.add(X86Reg.from_capstone(r).extended)
                sub_insts.insert(0, inst)

        return InstructionCollection(sub_insts), depends_regs

    def replace_with(self, from_idx, to_idx, insts):
        self._insts[from_idx:to_idx + 1] = insts
        return (to_idx - from_idx + 1) - len(insts)

    def to_list(self):
        return self._insts

    def duplicate(self):
        return InstructionCollection(list(self._insts))

    def remove(self, inst):
        self._insts.remove(inst)

    def tail(self, begin_idx):
        return self.__class__(self._insts[begin_idx:])

    def head(self, end_idx):
        return self.__class__(self._insts[:end_idx])

    def range_of(self, begin_idx, end_idx):
        return self.__class__(self._insts[begin_idx:end_idx])

    def __getitem__(self, item):
        return self._insts[item]

    def __len__(self):
        return len(self._insts)

    def __add__(self, other):
        return self.__class__(self._insts + other._insts)


def unpack_int(val_bytes: bytes, size: int) -> int:
    if size == 1:
        return st.unpack("<B", val_bytes)[0]
    elif size == 2:
        return st.unpack("<H", val_bytes)[0]
    elif size == 4:
        return st.unpack("<I", val_bytes)[0]
    elif size == 8:
        return st.unpack("<Q", val_bytes)[0]
    else:
        raise ValueError("Invalid size: {}".format(size))


def pack_int(int_val: int, size: int) -> bytes:
    if size == 1:
        return st.pack("<B", int_val)
    elif size == 2:
        return st.pack("<H", int_val)
    elif size == 4:
        return st.pack("<I", int_val)
    elif size == 8:
        return st.pack("<Q", int_val)
    else:
        raise ValueError("Invalid size: {}".format(size))


def str_to_cs_inst(inst_str: str, address: int = 0) -> cs.CsInsn:
    a = get_shared_ks()
    d = get_shared_md()
    code_bytes = bytes(a.asm(inst_str.encode('utf-8'))[0])
    inst = next(d.disasm(code_bytes, address))
    return inst
