import capstone
import capstone.x86_const as x86
import ida_bytes
import ida_ua
import idaapi
import idc
import ida_funcs
import ida_allins

ea = idc.get_screen_ea()

x64md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
x64md.detail = True


class VRef:
    def __init__(self):
        self.uses = set()
        self.users = set()

    def add_use(self, use):
        use.users.add(self)
        self.uses.add(use)

    def remove_use(self, use):
        use.users.remove(self)
        self.uses.remove(use)

    def remove_all_uses(self):
        for use in self.uses:
            use.users.remove(self)
        self.uses = set()


class VRegister(VRef):
    def __init__(self, reg_name):
        super().__init__()
        self.reg_name = reg_name

    def __str__(self):
        return self.reg_name


class VInstruction(VRef):
    def __init__(self, ida_insn: ida_ua.insn_t, cs_insn: capstone.CsInsn):
        super(VInstruction, self).__init__()
        self.ida = ida_insn
        self.cs = cs_insn
        self.parent = None

    def cs_dump(self):
        return "%x:\t%s\t%s" % (self.cs.address, self.cs.mnemonic, self.cs.op_str)

    def __str__(self):
        return self.cs_dump()


class VBasicBlock:
    def __init__(self, start_ea, end_ea, parent):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.predecessors = []
        self.successors = []
        self.instructions = []
        self.parent = None

    def get_last_instruction(self) -> VInstruction:
        return self.instructions[-1]

    def add_instruction(self, insn: VInstruction):
        self.instructions.append(insn)
        insn.parent = self


class VFunction:
    def __init__(self, ea):
        self.ea = ea
        self.ida = ida_funcs.get_func(ea)
        print(hex(ea))
        fc = idaapi.FlowChart(self.ida, flags=idaapi.FC_PREDS)
        self.blocks = [VBasicBlock(bb.start_ea, bb.end_ea, self) for bb in fc]
        self.build_cfg()
        # self.blocks = []
        # sz = 100
        # ea = self.ida.start_ea
        # while sz > 0:
        #     ida_insn = ida_ua.insn_t()
        #     ida_insn_len = ida_ua.decode_insn(ida_insn, ea)
        #
        #     cs_insn = next(x64md.disasm(ida_bytes.get_bytes(ida_insn.ea, ida_insn.size), ida_insn.ea))
        #     print("%x:\t%s\t%s" % (cs_insn.address, cs_insn.mnemonic, cs_insn.op_str))
        #
        #     if cs_insn.id == x86.X86_INS_JMP:
        #         op = cs_insn.operands[0]
        #         if op.type == capstone.CS_OP_IMM:
        #             ea = op.imm
        #             print("JMP", hex(op.imm))
        #         elif op.type == capstone.CS_OP_REG:
        #             break
        #     else:
        #         ea += ida_insn_len
        #
        #     sz -= 1



    def find_basic_block(self, ea):
        for vbb in self.blocks:
            if vbb.start_ea <= ea and ea < vbb.end_ea:
                return vbb
        return None

    def build_cfg(self):
        for vbb in self.blocks:
            print(vbb.end_ea - vbb.start_ea)
            ea = vbb.start_ea
            while ea < vbb.end_ea:

                ida_insn = ida_ua.insn_t()
                ida_ua.decode_insn(ida_insn, ea)

                # get capstone instruction
                cs_insn = next(x64md.disasm(ida_bytes.get_bytes(ida_insn.ea, ida_insn.size), ida_insn.ea))

                vbb.add_instruction(VInstruction(ida_insn=ida_insn, cs_insn=cs_insn))
                ea += ida_insn.size

            last_vi = vbb.get_last_instruction()
            sux_vbb = None
            if last_vi.ida.itype == ida_allins.NN_jmp:
                sux_vbb = self.find_basic_block(last_vi.ida.ops[0].addr)

            if not sux_vbb:
                sux_vbb = self.find_basic_block(vbb.end_ea + 1)

            if sux_vbb:
                vbb.successors.append(sux_vbb)
                sux_vbb.predecessors.append(vbb)

    def insns(self):
        for vbb in self.blocks:
            for vi in vbb.instructions:
                yield vi

    def _dfs_block(self, vbb,  visited: set):
        if vbb in visited:
            return
        visited.add(vbb)
        for pre in vbb.predecessors:
            yield from self._dfs_block(pre, visited)
        yield vbb

    def deep_first(self):
        visited = set()
        for vbb in self.blocks:
            yield from self._dfs_block(vbb, visited)

    def inverse_deep_first(self):
        return reversed(list(self.deep_first()))


class Helper:

    @staticmethod
    def get_reg_generic_name(reg):
        if reg in [x86.X86_REG_AL, x86.X86_REG_AH, x86.X86_REG_AX, x86.X86_REG_EAX, x86.X86_REG_RAX]:
            return "rax"
        elif reg in [x86.X86_REG_BL, x86.X86_REG_BH, x86.X86_REG_BX, x86.X86_REG_EBX, x86.X86_REG_RBX]:
            return "rbx"
        elif reg in [x86.X86_REG_CL, x86.X86_REG_CH, x86.X86_REG_CX, x86.X86_REG_ECX, x86.X86_REG_RCX]:
            return "rcx"
        elif reg in [x86.X86_REG_DL, x86.X86_REG_DH, x86.X86_REG_DX, x86.X86_REG_EDX, x86.X86_REG_RDX]:
            return "rdx"
        elif reg in [x86.X86_REG_SIL, x86.X86_REG_SI, x86.X86_REG_ESI, x86.X86_REG_RSI]:
            return "rsi"
        elif reg in [x86.X86_REG_DIL, x86.X86_REG_DI, x86.X86_REG_EDI, x86.X86_REG_RDI]:
            return "rdi"
        elif reg in [x86.X86_REG_SPL, x86.X86_REG_SP, x86.X86_REG_ESP, x86.X86_REG_RSP]:
            return "rsp"
        elif reg in [x86.X86_REG_BPL, x86.X86_REG_BP, x86.X86_REG_EBP, x86.X86_REG_RBP]:
            return "rbp"
        elif reg in [x86.X86_REG_R8B, x86.X86_REG_R8W, x86.X86_REG_R8D, x86.X86_REG_R8]:
            return "r8"
        elif reg in [x86.X86_REG_R9B, x86.X86_REG_R9W, x86.X86_REG_R9D, x86.X86_REG_R9]:
            return "r9"
        elif reg in [x86.X86_REG_R10B, x86.X86_REG_R10W, x86.X86_REG_R10D, x86.X86_REG_R10]:
            return "r10"
        elif reg in [x86.X86_REG_R11B, x86.X86_REG_R11W, x86.X86_REG_R11D, x86.X86_REG_R11]:
            return "r11"
        elif reg in [x86.X86_REG_R12B, x86.X86_REG_R12W, x86.X86_REG_R12D, x86.X86_REG_R12]:
            return "r12"
        elif reg in [x86.X86_REG_R13B, x86.X86_REG_R13W, x86.X86_REG_R13D, x86.X86_REG_R13]:
            return "r13"
        elif reg in [x86.X86_REG_R14B, x86.X86_REG_R14W, x86.X86_REG_R14D, x86.X86_REG_R14]:
            return "r14"
        elif reg in [x86.X86_REG_R15B, x86.X86_REG_R15W, x86.X86_REG_R15D, x86.X86_REG_R15]:
            return "r15"
        elif reg in [x86.X86_REG_IP, x86.X86_REG_EIP, x86.X86_REG_RIP]:
            return "rip"
        elif reg == x86.X86_REG_EFLAGS:
            return "eflags"
        else:
            return str(reg)

    @staticmethod
    def has_side_effect(cs_i):
        # TODO this method is incomplete, add more assertions if needed.
        # Check is stack related operation

        if cs_i.id in [x86.X86_INS_PUSH, x86.X86_INS_PUSHF, x86.X86_INS_PUSHFD, x86.X86_INS_PUSHFQ,
                           x86.X86_INS_PUSHAL, x86.X86_INS_PUSHAW,
                           x86.X86_INS_POP, x86.X86_INS_POPF, x86.X86_INS_POPFD, x86.X86_INS_POPFQ,
                           x86.X86_INS_POPAL, x86.X86_INS_POPAW]:
            return True

        if cs_i.group(capstone.CS_GRP_JUMP):
            return True

        if cs_i.group(capstone.CS_GRP_CALL):
            return True

        if cs_i.group(capstone.CS_GRP_RET):
            return True

        if cs_i.group(capstone.CS_GRP_IRET):
            return True

        if cs_i.id in [x86.X86_INS_JMP]:
            return True

        ops = cs_i.operands
        # Check has mem write
        for op in ops:  # op: capstone.x86.X86Op
            if op.type == capstone.CS_OP_MEM and (op.access & capstone.CS_AC_WRITE):
                return True

        return False

    @staticmethod
    def is_reversed(cs_i):

        ops = cs_i.operands
        if not ops:
            return False

        if ops[0].type == capstone.CS_OP_REG:
            if ops[0].reg == x86.X86_REG_R9 and (ops[0].access & capstone.CS_AC_WRITE):
                return True
            if len(ops) > 1 and ops[0].reg == x86.X86_REG_RSI and (ops[0].access & capstone.CS_AC_WRITE) \
                    and ops[1].reg == x86.X86_REG_RSP:
                return True
        return False


v_x64_regs = {
    'rax': VRegister('rax'),
    'rbx': VRegister('rbx'),
    'rcx': VRegister('rcx'),
    'rdx': VRegister('rdx'),
    'rsi': VRegister('rsi'),
    'rdi': VRegister('rdi'),
    'rbp': VRegister('rbp'),
    'rsp': VRegister('rsp'),
    'r8': VRegister('r8'),
    'r9': VRegister('r9'),
    'r10': VRegister('r10'),
    'r11': VRegister('r11'),
    'r12': VRegister('r12'),
    'r13': VRegister('r13'),
    'r14': VRegister('r14'),
    'r15': VRegister('r15'),
    'rip': VRegister('rip'),
    'eflags': VRegister('eflags')
}

print("===== Calculate use-def chain =====")
last_reg_defs_map = {}

def find_defs(reg_name, vbb):
    vbb_last_reg_defs = last_reg_defs_map[vbb]
    if reg_name in vbb_last_reg_defs:
        yield vbb_last_reg_defs[reg_name]
    elif vbb.predecessors:
        for pred in vbb.predecessors:
            yield from find_defs(reg_name, pred)
    else:
        yield v_x64_regs[reg_name]


vf = VFunction(ea)

for vbb in vf.deep_first():
    last_reg_defs_map[vbb] = {}
    for vi in vbb.instructions:
        # print(vi.cs_dump())

        cs_reg_uses, cs_reg_defs = vi.cs.regs_access()
        for reg in cs_reg_uses:
            reg_name = Helper.get_reg_generic_name(reg)
            for def_vi in find_defs(reg_name, vbb):
                vi.add_use(def_vi)
                # print(f" Use [{reg_name}] from: {def_vi}")

        for reg in cs_reg_defs:
            reg_name = Helper.get_reg_generic_name(reg)
            last_reg_defs_map[vbb][reg_name] = vi


print("===== Print use =====")

candidates = []
for vi in vf.insns():
    if vi.cs.id == x86.X86_INS_NOP:
        continue

    # print(vi.cs_dump())
    # for use in vi.uses:
    #     print(f" Use: {use}")

    if Helper.is_reversed(vi.cs) or Helper.has_side_effect(vi.cs):
        continue

    candidates.append(vi)


print("===== Delete dead instructions =====")
while True:
    dead_vi = None
    for vi in reversed(candidates):
        if len(vi.users) == 0:
            dead_vi = vi
            break

    if dead_vi:
        candidates.remove(dead_vi)
        dead_vi.remove_all_uses()

        print(dead_vi.cs_dump())
        ida_bytes.patch_bytes(dead_vi.ida.ea, b'\x90' * dead_vi.ida.size)
    else:
        break
