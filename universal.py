import unicorn.x86_const as uc_x86
import capstone.x86 as cs_x86
import enum

K_META_CAPSTONE2 = '_cs2'
K_META_2CAPSTONE = '_2cs'
K_META_UNICORN2 = '_uc2'
K_META_2UNICORN = '_2uc'
K_META_EXTEND2 = '_ext2'
K_META_2NAME = '_2name'

_X86RegMeta = {}


class X86Reg(enum.Enum):
    INVALID = 0

    RAX = 1000
    RBX = 1001
    RCX = 1002
    RDX = 1003
    RSI = 1004
    RDI = 1005
    RSP = 1006
    RBP = 1007
    R8 = 1008
    R9 = 1009
    R10 = 1010
    R11 = 1011
    R12 = 1012
    R13 = 1013
    R14 = 1014
    R15 = 1015

    EAX = 2000
    EBX = 2001
    ECX = 2002
    EDX = 2003
    ESI = 2004
    EDI = 2005
    EBP = 2006
    ESP = 2007
    R8D = 2008
    R9D = 2009
    R10D = 2010
    R11D = 2011
    R12D = 2012
    R13D = 2013
    R14D = 2014
    R15D = 2015

    AX = 3000
    BX = 3001
    CX = 3002
    DX = 3003
    SI = 3004
    DI = 3005
    SP = 3006
    BP = 3007
    R8W = 3008
    R9W = 3009
    R10W = 3010
    R11W = 3011
    R12W = 3012
    R13W = 3013
    R14W = 3014
    R15W = 3015

    AL = 4000
    BL = 4001
    CL = 4002
    DL = 4003
    SIL = 4004
    DIL = 4005
    SPL = 4006
    BPL = 4007
    R8B = 4008
    R9B = 4009
    R10B = 4010
    R11B = 4011
    R12B = 4012
    R13B = 4013
    R14B = 4014
    R15B = 4015

    AH = 5000
    BH = 5001
    CH = 5002
    DH = 5003

    RIP = 6000
    EFLAGS = 6001

    @classmethod
    def from_capstone(cls, cs_reg):
        return _X86RegMeta[K_META_CAPSTONE2][cs_reg]

    @classmethod
    def from_unicorn(cls, uc_reg):
        return _X86RegMeta[K_META_UNICORN2][uc_reg]

    @property
    def capstone(self):
        return _X86RegMeta[K_META_2CAPSTONE][self]

    @property
    def unicorn(self):
        return _X86RegMeta[K_META_2UNICORN][self]

    @property
    def name(self):
        return _X86RegMeta[K_META_2NAME][self]

    @property
    def extended(self):
        return _X86RegMeta[K_META_EXTEND2][self]

    def is_equal_to_capstone(self, cs_reg):
        return self.extended == self.__class__.from_capstone(cs_reg).extended

    def is_equal_to_unicorn(self, cs_reg):
        return self.extended == self.__class__.from_unicorn(cs_reg).extended

    @classmethod
    def capstone_convertible(cls, cs_reg):
        return cs_reg in _X86RegMeta[K_META_CAPSTONE2]

    @classmethod
    def unicorn_convertible(cls, uc_reg):
        return uc_reg in _X86RegMeta[K_META_UNICORN2]


if not _X86RegMeta:
    _X86RegMeta[K_META_EXTEND2] = {
        # 8 to 8
        X86Reg.RAX: X86Reg.RAX, X86Reg.RBX: X86Reg.RBX, X86Reg.RCX: X86Reg.RCX, X86Reg.RDX: X86Reg.RDX,
        X86Reg.RSI: X86Reg.RSI, X86Reg.RDI: X86Reg.RDI, X86Reg.RSP: X86Reg.RSP, X86Reg.RBP: X86Reg.RBP,
        X86Reg.R8: X86Reg.R8, X86Reg.R9: X86Reg.R9, X86Reg.R10: X86Reg.R10, X86Reg.R11: X86Reg.R11,
        X86Reg.R12: X86Reg.R12, X86Reg.R13: X86Reg.R13, X86Reg.R14: X86Reg.R14, X86Reg.R15: X86Reg.R15,
        # 4 to 8
        X86Reg.EAX: X86Reg.RAX, X86Reg.EBX: X86Reg.RBX, X86Reg.ECX: X86Reg.RCX, X86Reg.EDX: X86Reg.RDX,
        X86Reg.ESI: X86Reg.RSI, X86Reg.EDI: X86Reg.RDI,X86Reg.EBP: X86Reg.RBP, X86Reg.ESP: X86Reg.RSP,
        X86Reg.R8D: X86Reg.R8, X86Reg.R9D: X86Reg.R9, X86Reg.R10D: X86Reg.R10, X86Reg.R11D: X86Reg.R11,
        X86Reg.R12D: X86Reg.R12, X86Reg.R13D: X86Reg.R13, X86Reg.R14D: X86Reg.R14, X86Reg.R15D: X86Reg.R15,
        # 2 to 8
        X86Reg.AX: X86Reg.RAX, X86Reg.BX: X86Reg.RBX, X86Reg.CX: X86Reg.RCX, X86Reg.DX: X86Reg.RDX,
        X86Reg.SI: X86Reg.RSI, X86Reg.DI: X86Reg.RDI, X86Reg.BP: X86Reg.RBP, X86Reg.SP: X86Reg.RSP,
        X86Reg.R8W: X86Reg.R8, X86Reg.R9W: X86Reg.R9, X86Reg.R10W: X86Reg.R10, X86Reg.R11W: X86Reg.R11,
        X86Reg.R12W: X86Reg.R12, X86Reg.R13W: X86Reg.R13, X86Reg.R14W: X86Reg.R14, X86Reg.R15W: X86Reg.R15,
        # 1 to 8
        X86Reg.AL: X86Reg.RAX, X86Reg.BL: X86Reg.RBX, X86Reg.CL: X86Reg.RCX, X86Reg.DL: X86Reg.RDX,
        X86Reg.SIL: X86Reg.RSI, X86Reg.DIL: X86Reg.RDI, X86Reg. BPL: X86Reg.RBP, X86Reg.SPL: X86Reg.RSP,
        X86Reg.R8B: X86Reg.R8, X86Reg.R9B: X86Reg.R9, X86Reg.R10B: X86Reg.R10, X86Reg.R11B: X86Reg.R11,
        X86Reg.R12B: X86Reg.R12, X86Reg.R13B: X86Reg.R13, X86Reg.R14B: X86Reg.R14, X86Reg.R15B: X86Reg.R15,

        X86Reg.AH: X86Reg.RAX, X86Reg.BH: X86Reg.RBX, X86Reg.CH: X86Reg.RCX, X86Reg.DH: X86Reg.RDX,

        X86Reg.RIP: X86Reg.RIP, X86Reg.EFLAGS: X86Reg.EFLAGS
    }

    _X86RegMeta[K_META_2CAPSTONE] = {
        # 8-byte register
        X86Reg.RAX: cs_x86.X86_REG_RAX, X86Reg.RBX: cs_x86.X86_REG_RBX, X86Reg.RCX: cs_x86.X86_REG_RCX, X86Reg.RDX: cs_x86.X86_REG_RDX,
        X86Reg.RSI: cs_x86.X86_REG_RSI, X86Reg.RDI: cs_x86.X86_REG_RDI, X86Reg.RSP: cs_x86.X86_REG_RSP, X86Reg.RBP: cs_x86.X86_REG_RBP,
        X86Reg.R8: cs_x86.X86_REG_R8, X86Reg.R9: cs_x86.X86_REG_R9, X86Reg.R10: cs_x86.X86_REG_R10, X86Reg.R11: cs_x86.X86_REG_R11,
        X86Reg.R12: cs_x86.X86_REG_R12, X86Reg.R13: cs_x86.X86_REG_R13, X86Reg.R14: cs_x86.X86_REG_R14, X86Reg.R15: cs_x86.X86_REG_R15,
        # Bytes 0-3
        X86Reg.EAX: cs_x86.X86_REG_EAX, X86Reg.EBX: cs_x86.X86_REG_EBX, X86Reg.ECX: cs_x86.X86_REG_ECX, X86Reg.EDX: cs_x86.X86_REG_EDX,
        X86Reg.ESI: cs_x86.X86_REG_ESI, X86Reg.EDI: cs_x86.X86_REG_EDI, X86Reg.EBP: cs_x86.X86_REG_EBP, X86Reg.ESP: cs_x86.X86_REG_ESP,
        X86Reg.R8D: cs_x86.X86_REG_R8D, X86Reg.R9D: cs_x86.X86_REG_R9D, X86Reg.R10D: cs_x86.X86_REG_R10D, X86Reg.R11D: cs_x86.X86_REG_R11D,
        X86Reg.R12D: cs_x86.X86_REG_R12D, X86Reg.R13D: cs_x86.X86_REG_R13D, X86Reg.R14D: cs_x86.X86_REG_R14D, X86Reg.R15D: cs_x86.X86_REG_R15D,
        # Bytes 0-1
        X86Reg.AX: cs_x86.X86_REG_AX, X86Reg.BX: cs_x86.X86_REG_BX, X86Reg.CX: cs_x86.X86_REG_CX, X86Reg.DX: cs_x86.X86_REG_DX,
        X86Reg.SI: cs_x86.X86_REG_SI, X86Reg.DI: cs_x86.X86_REG_DI, X86Reg.SP: cs_x86.X86_REG_SP, X86Reg.BP: cs_x86.X86_REG_BP,
        X86Reg.R8W: cs_x86.X86_REG_R8W, X86Reg.R9W: cs_x86.X86_REG_R9W, X86Reg.R10W: cs_x86.X86_REG_R10W, X86Reg.R11W: cs_x86.X86_REG_R11W,
        X86Reg.R12W: cs_x86.X86_REG_R12W, X86Reg.R13W: cs_x86.X86_REG_R13W, X86Reg.R14W: cs_x86.X86_REG_R14W, X86Reg.R15W: cs_x86.X86_REG_R15W,

        # Bytes 0
        X86Reg.AL: cs_x86.X86_REG_AL, X86Reg.BL: cs_x86.X86_REG_BL, X86Reg.CL: cs_x86.X86_REG_CL, X86Reg.DL: cs_x86.X86_REG_DL,
        X86Reg.SIL: cs_x86.X86_REG_SIL, X86Reg.DIL: cs_x86.X86_REG_DIL, X86Reg.SPL: cs_x86.X86_REG_SPL, X86Reg.BPL: cs_x86.X86_REG_BPL,
        X86Reg.R8B: cs_x86.X86_REG_R8B, X86Reg.R9B: cs_x86.X86_REG_R9B, X86Reg.R10B: cs_x86.X86_REG_R10B, X86Reg.R11B: cs_x86.X86_REG_R11B,
        X86Reg.R12B: cs_x86.X86_REG_R12B, X86Reg.R13B: cs_x86.X86_REG_R13B, X86Reg.R14B: cs_x86.X86_REG_R14B, X86Reg.R15B: cs_x86.X86_REG_R15B,

        X86Reg.AH: cs_x86.X86_REG_AH, X86Reg.BH: cs_x86.X86_REG_BH, X86Reg.CH: cs_x86.X86_REG_CH, X86Reg.DH: cs_x86.X86_REG_DH,

        X86Reg.RIP: cs_x86.X86_REG_RIP, X86Reg.EFLAGS: cs_x86.X86_REG_EFLAGS,
        X86Reg.INVALID: cs_x86.X86_REG_INVALID
    }
    _X86RegMeta[K_META_CAPSTONE2] = dict((v, k) for k, v in _X86RegMeta[K_META_2CAPSTONE].items())

    _X86RegMeta[K_META_2UNICORN] = {
        # 8-byte register
        X86Reg.RAX: uc_x86.UC_X86_REG_RAX, X86Reg.RBX: uc_x86.UC_X86_REG_RBX, X86Reg.RCX: uc_x86.UC_X86_REG_RCX, X86Reg.RDX: uc_x86.UC_X86_REG_RDX,
        X86Reg.RSI: uc_x86.UC_X86_REG_RSI, X86Reg.RDI: uc_x86.UC_X86_REG_RDI, X86Reg.RSP: uc_x86.UC_X86_REG_RSP, X86Reg.RBP: uc_x86.UC_X86_REG_RBP,
        X86Reg.R8: uc_x86.UC_X86_REG_R8, X86Reg.R9: uc_x86.UC_X86_REG_R9, X86Reg.R10: uc_x86.UC_X86_REG_R10, X86Reg.R11: uc_x86.UC_X86_REG_R11,
        X86Reg.R12: uc_x86.UC_X86_REG_R12, X86Reg.R13: uc_x86.UC_X86_REG_R13, X86Reg.R14: uc_x86.UC_X86_REG_R14, X86Reg.R15: uc_x86.UC_X86_REG_R15,
        # Bytes 0-3
        X86Reg.EAX: uc_x86.UC_X86_REG_EAX, X86Reg.EBX: uc_x86.UC_X86_REG_EBX, X86Reg.ECX: uc_x86.UC_X86_REG_ECX, X86Reg.EDX: uc_x86.UC_X86_REG_EDX,
        X86Reg.ESI: uc_x86.UC_X86_REG_ESI, X86Reg.EDI: uc_x86.UC_X86_REG_EDI, X86Reg.EBP: uc_x86.UC_X86_REG_EBP, X86Reg.ESP: uc_x86.UC_X86_REG_ESP,
        X86Reg.R8D: uc_x86.UC_X86_REG_R8D, X86Reg.R9D: uc_x86.UC_X86_REG_R9D, X86Reg.R10D: uc_x86.UC_X86_REG_R10D, X86Reg.R11D: uc_x86.UC_X86_REG_R11D,
        X86Reg.R12D: uc_x86.UC_X86_REG_R12D, X86Reg.R13D: uc_x86.UC_X86_REG_R13D, X86Reg.R14D: uc_x86.UC_X86_REG_R14D, X86Reg.R15D: uc_x86.UC_X86_REG_R15D,
        # Bytes 0-1
        X86Reg.AX: uc_x86.UC_X86_REG_AX, X86Reg.BX: uc_x86.UC_X86_REG_BX, X86Reg.CX: uc_x86.UC_X86_REG_CX, X86Reg.DX: uc_x86.UC_X86_REG_DX,
        X86Reg.SI: uc_x86.UC_X86_REG_SI, X86Reg.DI: uc_x86.UC_X86_REG_DI, X86Reg.SP: uc_x86.UC_X86_REG_SP, X86Reg.BP: uc_x86.UC_X86_REG_BP,
        X86Reg.R8W: uc_x86.UC_X86_REG_R8W, X86Reg.R9W: uc_x86.UC_X86_REG_R9W, X86Reg.R10W: uc_x86.UC_X86_REG_R10W, X86Reg.R11W: uc_x86.UC_X86_REG_R11W,
        X86Reg.R12W: uc_x86.UC_X86_REG_R12W, X86Reg.R13W: uc_x86.UC_X86_REG_R13W, X86Reg.R14W: uc_x86.UC_X86_REG_R14W, X86Reg.R15W: uc_x86.UC_X86_REG_R15W,
        # Bytes 0
        X86Reg.AL: uc_x86.UC_X86_REG_AL, X86Reg.BL: uc_x86.UC_X86_REG_BL, X86Reg.CL: uc_x86.UC_X86_REG_CL, X86Reg.DL: uc_x86.UC_X86_REG_DL,
        X86Reg.SIL: uc_x86.UC_X86_REG_SIL, X86Reg.DIL: uc_x86.UC_X86_REG_DIL, X86Reg.SPL: uc_x86.UC_X86_REG_SPL, X86Reg.BPL: uc_x86.UC_X86_REG_BPL,
        X86Reg.R8B: uc_x86.UC_X86_REG_R8B, X86Reg.R9B: uc_x86.UC_X86_REG_R9B, X86Reg.R10B: uc_x86.UC_X86_REG_R10B, X86Reg.R11B: uc_x86.UC_X86_REG_R11B,
        X86Reg.R12B: uc_x86.UC_X86_REG_R12B, X86Reg.R13B: uc_x86.UC_X86_REG_R13B, X86Reg.R14B: uc_x86.UC_X86_REG_R14B, X86Reg.R15B: uc_x86.UC_X86_REG_R15B,

        X86Reg.AH: uc_x86.UC_X86_REG_AH, X86Reg.BH: uc_x86.UC_X86_REG_BH, X86Reg.CH: uc_x86.UC_X86_REG_CH, X86Reg.DH: uc_x86.UC_X86_REG_DH,

        X86Reg.RIP: uc_x86.UC_X86_REG_RIP, X86Reg.EFLAGS: uc_x86.UC_X86_REG_EFLAGS,
        X86Reg.INVALID: uc_x86.UC_X86_REG_INVALID
    }

    _X86RegMeta[K_META_UNICORN2] = dict((v, k) for k, v in _X86RegMeta[K_META_2UNICORN].items())

    _X86RegMeta[K_META_2NAME] = {
        # 8-byte register
        X86Reg.RAX: 'RAX', X86Reg.RBX: 'RBX', X86Reg.RCX: 'RCX', X86Reg.RDX: 'RDX',
        X86Reg.RSI: 'RSI', X86Reg.RDI: 'RDI', X86Reg.RSP: 'RSP', X86Reg.RBP: 'RBP',
        X86Reg.R8: 'R8', X86Reg.R9: 'R9', X86Reg.R10: 'R10', X86Reg.R11: 'R11',
        X86Reg.R12: 'R12', X86Reg.R13: 'R13', X86Reg.R14: 'R14', X86Reg.R15: 'R15',
        # Bytes 0-3
        X86Reg.EAX: 'EAX', X86Reg.EBX: 'EBX', X86Reg.ECX: 'ECX', X86Reg.EDX: 'EDX',
        X86Reg.ESI: 'ESI', X86Reg.EDI: 'EDI', X86Reg.EBP: 'EBP', X86Reg.ESP: 'ESP',
        X86Reg.R8D: 'R8D', X86Reg.R9D: 'R9D', X86Reg.R10D: 'R10D', X86Reg.R11D: 'R11D',
        X86Reg.R12D: 'R12D', X86Reg.R13D: 'R13D', X86Reg.R14D: 'R14D', X86Reg.R15D: 'R15D',
        # Bytes 0-1
        X86Reg.AX: 'AX', X86Reg.BX: 'BX', X86Reg.CX: 'CX', X86Reg.DX: 'DX',
        X86Reg.SI: 'SI', X86Reg.DI: 'DI', X86Reg.SP: 'SP', X86Reg.BP: 'BP',
        X86Reg.R8W: 'R8W', X86Reg.R9W: 'R9W', X86Reg.R10W: 'R10W', X86Reg.R11W: 'R11W',
        X86Reg.R12W: 'R12W', X86Reg.R13W: 'R13W', X86Reg.R14W: 'R14W', X86Reg.R15W: 'R15W',
        # Bytes 0
        X86Reg.AL: 'AL', X86Reg.BL: 'BL', X86Reg.CL: 'CL', X86Reg.DL: 'DL',
        X86Reg.SIL: 'SIL', X86Reg.DIL: 'DIL', X86Reg.SPL: 'SPL', X86Reg.BPL: 'BPL',
        X86Reg.R8B: 'R8B', X86Reg.R9B: 'R9B', X86Reg.R10B: 'R10B', X86Reg.R11B: 'R11B',
        X86Reg.R12B: 'R12B', X86Reg.R13B: 'R13B', X86Reg.R14B: 'R14B', X86Reg.R15B: 'R15B',

        X86Reg.RIP: 'RIP', X86Reg.EFLAGS: 'EFLAGS'
    }
    a = X86Reg.RAX
