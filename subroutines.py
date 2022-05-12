import capstone as cs
import capstone.x86 as cs_x86
from lief.PE import Binary

from architecture import VMArchitecture
from utils import InstructionCollection, xor_sized, imatch, Mod2NInt, emulate_shared
from universal import X86Reg
from entities import VMState, VMHandler, VMEncryptedValue
from optimizers import VMOptimizer


def update_vip_direction(state: VMState, cursor: int, ic: InstructionCollection):
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

    vip_dir = VMState.VIPDirection.UNSPECIFIED
    if forward_idx != -1:
        vip_dir = VMState.VIPDirection.FORWARD
    elif backward_idx != -1:
        vip_dir = VMState.VIPDirection.BACKWARD
    else:
        raise Exception("vip direction not determined")

    state.update_vip_direction(vip_dir)


def decrypt_value(state: VMState, def_reg: X86Reg, encrypted_value: int, value_size: int, cursor: int,
                  ic: InstructionCollection):
    def _decryption_begin_finder(i):
        # ----------------------------------------------------
        # xor vkr_reg, def_reg
        # ----------------------------------------------------
        return imatch(i, cs.x86.X86_INS_XOR, cs.x86.X86_OP_REG, cs.x86.X86_OP_REG) and \
               def_reg.is_equal_to_capstone(i.operands[0].reg) and \
               state.vrk_reg.is_equal_to_capstone(i.operands[1].reg)

    def _decryption_end_finder_1(i):
        if imatch(i, cs.x86.X86_INS_XOR, cs.x86.X86_OP_REG, cs.x86.X86_OP_REG):
            # ----------------------------------------------------
            # xor def_reg, vrk_reg
            # ----------------------------------------------------
            return state.vrk_reg.is_equal_to_capstone(i.operands[0].reg)
        return False

    def _decryption_end_finder_2(i):
        if imatch(i, cs.x86.X86_INS_XOR, cs.CS_OP_MEM, cs.x86.X86_OP_REG):
            # ----------------------------------------------------
            # push vrk_reg
            # xor [rsp], def_reg
            # pop vrk_reg
            # ----------------------------------------------------
            return def_reg.is_equal_to_capstone(i.operands[1].reg) and \
                   i.operands[0].mem.base == cs_x86.X86_REG_RSP and \
                   i.operands[0].mem.disp == 0 and \
                   i.operands[0].mem.scale == 1
        return False

    def _decryption_end_finder(i):
        if imatch(i, cs.x86.X86_INS_XOR, cs.x86.X86_OP_REG, cs.x86.X86_OP_REG):
            # ----------------------------------------------------
            # xor def_reg, vrk_reg
            # ----------------------------------------------------
            return state.vrk_reg.is_equal_to_capstone(i.operands[0].reg)
        elif imatch(i, cs.x86.X86_INS_XOR, cs.CS_OP_MEM, cs.x86.X86_OP_REG):
            # ----------------------------------------------------
            # push vrk_reg
            # xor [rsp], def_reg
            # pop vrk_reg
            # ----------------------------------------------------
            return def_reg.is_equal_to_capstone(i.operands[1].reg) and \
                   i.operands[0].mem.base == cs_x86.X86_REG_RSP and \
                   i.operands[0].mem.disp == 0 and \
                   i.operands[0].mem.scale == 1
        return False

    begin_idx, begin_i = ic.next_by(cursor, _decryption_begin_finder)
    assert begin_idx != -1 and "decryption begin idx not found"

    assert def_reg.is_equal_to_capstone(begin_i.operands[0].reg) and "def_reg is not equal to begin_i.operands[0].reg"
    # cast type
    def_reg = X86Reg.from_capstone(begin_i.operands[0].reg)

    end_idx = ic.next_index_by(begin_idx + 1, _decryption_end_finder_1)
    # assert end_idx != -1 and "decryption end idx not found"

    def _push_finder(i):
        return imatch(i, cs.x86.X86_INS_PUSH, cs.x86.X86_OP_REG) and \
               state.vrk_reg.is_equal_to_capstone(i.operands[0].reg)

    def _pop_finder(i):
        return imatch(i, cs.x86.X86_INS_POP, cs.x86.X86_OP_REG) and \
               state.vrk_reg.is_equal_to_capstone(i.operands[0].reg)

    if end_idx != -1:
        push_idx = ic.prev_index_by(end_idx, _push_finder)
        pop_idx = ic.next_index_by(end_idx, _pop_finder)
        if push_idx != -1 and push_idx < end_idx < pop_idx:
            end_idx = ic.next_index_by(push_idx + 1, _decryption_end_finder_2)
    else:
        end_idx = ic.next_index_by(begin_idx + 1, _decryption_end_finder_2)

    # begin_idx, begin_i = ic.next_by(cursor, _decryption_begin_finder)
    # assert begin_idx != -1 and "decryption begin idx not found"
    #
    # assert def_reg.is_equal_to_capstone(begin_i.operands[0].reg) and "def_reg is not equal to begin_i.operands[0].reg"
    # # cast type
    # def_reg = X86Reg.from_capstone(begin_i.operands[0].reg)
    #
    # end_idx = ic.next_index_by(begin_idx + 1, _decryption_end_finder)
    # assert end_idx != -1 and "decryption end idx not found"

    sub_ic, _ = ic.trace(def_reg.extended, begin_idx + 1, end_idx - 1)

    if imatch(ic[end_idx], cs.x86.X86_INS_XOR, cs.CS_OP_MEM, cs.x86.X86_OP_REG):
        def _pop_finder2(i):
            return imatch(i, cs.x86.X86_INS_POP, cs.x86.X86_OP_REG) and \
                     state.vrk_reg.is_equal_to_capstone(i.operands[0].reg)
        end_idx = ic.next_index_by(end_idx, _pop_finder2)

    entity = VMEncryptedValue(blk_start=begin_idx, blk_end=end_idx, def_reg=def_reg,
                              encrypted_value=encrypted_value, value_size=value_size,
                              transforms=sub_ic)
    entity.decrypt(state=state)
    return entity


def next_parameter(state: VMState, cursor: int, ic: InstructionCollection):
    if state.vip_direction == 0:
        raise Exception("vip direction is not determined")

    def _def_finder(i):
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

    idx, def_reg_i = ic.next_by(cursor, _def_finder)

    if idx == -1:
        return None

    def_reg = X86Reg.from_capstone(def_reg_i.operands[0].reg)
    value_size = def_reg_i.operands[1].size
    encrypted_value = state.read_vip(value_size)
    entity = decrypt_value(state=state, def_reg=def_reg, encrypted_value=encrypted_value, value_size=value_size,
                           cursor=idx + 1, ic=ic)
    return entity


class VMEntryParser:

    @classmethod
    def _get_encrypted_vip(cls, ic: InstructionCollection):
        # ----------------------------------------------------
        # push XXXXXX
        # ----------------------------------------------------
        assert imatch(ic[0], cs_x86.X86_INS_PUSH, cs.CS_OP_IMM) and "encrypted vip not found"
        return 0, ic[0].operands[0].imm

    @classmethod
    def _get_vip_reg(cls, cursor: int, ic: InstructionCollection):
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
    def _get_vsp_reg(cls, cursor: int, ic: InstructionCollection):
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
    def _get_vrk_reg(cls, cursor: int, vip_reg: X86Reg, ic: InstructionCollection):
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
    def _get_reloc_rva(cls, cursor: int, ic: InstructionCollection):
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
    def _decrypt_vip(cls, encrypted_vip: int, vip_reg: X86Reg,
                     vip_i_idx, vsp_id_idx, ic: InstructionCollection):
        sub_ic, depends = ic.trace(vip_reg, vip_i_idx + 1, vsp_id_idx - 1)
        assert len(sub_ic) and "can not decrypt vip"

        code_bytes = sub_ic.get_all_bytes()
        out_reg_values = emulate_shared(code_bytes, {vip_reg: encrypted_vip}, [vip_reg])

        return out_reg_values[vip_reg]

    @classmethod
    def parse(cls, binary: Binary, ic: InstructionCollection):
        encrypted_vip_idx, encrypted_vip = cls._get_encrypted_vip(ic)
        vip_i_idx, vip_reg = cls._get_vip_reg(encrypted_vip_idx + 1, ic)
        vsp_i_idx, vsp_reg = cls._get_vsp_reg(vip_i_idx + 1, ic)
        vrk_i_idx, vrk_reg = cls._get_vrk_reg(vsp_i_idx + 1, vip_reg, ic)
        reloc_rva_i_idx, reloc_rva = cls._get_reloc_rva(vrk_i_idx + 1, ic)

        loaded_vip_va = cls._decrypt_vip(encrypted_vip, vip_reg, vip_i_idx, vsp_i_idx, ic)

        rolling_key = loaded_vip_va
        vip_rva = loaded_vip_va - binary.optional_header.imagebase

        state = VMState(binary=binary, vsp_reg=vsp_reg, vip_reg=vip_reg, vrk_reg=vrk_reg,
                        vip_rva=vip_rva, rolling_key=rolling_key, reloc_rva=reloc_rva)
        update_vip_direction(state, vsp_i_idx + 1, ic)

        first_handler_off = next_parameter(state, vrk_i_idx + 1, ic)
        first_handler_rva = Mod2NInt.normalize(reloc_rva + first_handler_off.decrypted_value, 32)
        return state, first_handler_rva


class VMSwapParser:
    @classmethod
    def _find_self_ref(cls, state: VMState, cursor: int, ic: InstructionCollection):
        def _finder(i):
            # ----------------------------------------------------
            # lea r64, [$]
            # ----------------------------------------------------
            return imatch(i, cs_x86.X86_INS_LEA, cs.CS_OP_REG, cs.CS_OP_MEM) and \
                   i.operands[1].mem.disp == -7 and \
                   i.operands[1].mem.scale == 1 and \
                   i.operands[1].mem.base == cs_x86.X86_REG_RIP

        idx, def_i = ic.next_by(cursor, _finder)
        if idx == -1:
            return -1, None
        else:
            return idx, X86Reg.from_capstone(def_i.operands[0].reg).extended

    @classmethod
    def parse(cls, state: VMState, ic: InstructionCollection):
        # ----------------------------------------------------
        # mov r64, [vsp]
        # ----------------------------------------------------
        if imatch(ic[0], cs_x86.X86_INS_MOV, cs.CS_OP_REG, cs.CS_OP_MEM):
            read_vsp_i = ic[0]
            vip_from_reg = X86Reg.from_capstone(read_vsp_i.operands[0].reg)
            # ----------------------------------------------------
            # movabs r64, imm
            # ----------------------------------------------------
            idx_mutation_end = ic.next_index(1, cs_x86.X86_INS_MOVABS, cs.CS_OP_REG, cs.CS_OP_IMM)

            reg_mapping = {}
            for cs_reg in range(cs_x86.X86_REG_INVALID + 1, cs_x86.X86_REG_ENDING):
                if X86Reg.capstone_convertible(cs_reg):
                    u_reg = X86Reg.from_capstone(cs_reg).extended
                    reg_mapping[u_reg] = [0, u_reg]

            for inst_idx in range(1, idx_mutation_end):
                inst = ic[inst_idx]

                if len(inst.operands) != 2:
                    continue
                if inst.operands[0].size != 8:
                    continue

                if imatch(inst, cs_x86.X86_INS_MOV, cs.CS_OP_REG, cs.CS_OP_REG):
                    # ----------------------------------------------------
                    # mov r64, r64
                    # ----------------------------------------------------
                    r1 = X86Reg.from_capstone(inst.operands[0].reg)
                    r2 = X86Reg.from_capstone(inst.operands[1].reg)
                    reg_mapping[r1] = (inst_idx, reg_mapping[r2][1])
                elif imatch(inst, cs_x86.X86_INS_XCHG, cs.CS_OP_REG, cs.CS_OP_REG):
                    # ----------------------------------------------------
                    # xchg r64, r64
                    # ----------------------------------------------------
                    r1 = X86Reg.from_capstone(inst.operands[0].reg)
                    r2 = X86Reg.from_capstone(inst.operands[1].reg)
                    # swap
                    tmp = reg_mapping[r1][1]
                    reg_mapping[r1][1] = (inst_idx, reg_mapping[r2][1])
                    reg_mapping[r2][1] = tmp

                    reg_mapping[r1][0] = inst_idx
                    reg_mapping[r2][1] = inst_idx

            def _inherits_from(reg):
                inheritance = []
                for k, v in reg_mapping.items():
                    if v[1] == reg:
                        inheritance.append([v[0], k])
                inheritance.sort(key=lambda x: x[0])
                return inheritance

            vip_inh = _inherits_from(vip_from_reg)
            vsp_inh = _inherits_from(state.vsp_reg)

            if len(vip_inh) == 1:
                vip_inh.insert(0, [0, vip_from_reg])

            # print(vip_inh)
            # print(vsp_inh)
            new_vip_reg = vip_inh[0][1]
            new_vsp_reg = state.vsp_reg if len(vsp_inh) == 0 else vsp_inh[-1][1]
            new_vrk_reg = vip_inh[1][1]

            pfx_end = vip_inh[0][0]
            if vsp_inh:
                pfx_end = max(pfx_end, vsp_inh[-1][0])

            if pfx_end == 0 and len(vip_inh) >= 2:
                pfx_end = pfx_end - vip_inh[1][0]

            pfx_ic = ic.range_of(0, pfx_end)
            pfx_ic = VMOptimizer.process(state, [], pfx_ic)

            print(f"Before swap: VSP_REG: {state.vsp_reg} VIP_REG: {state.vip_reg} VRK_REG: {state.vrk_reg}")
            state.swap(new_vsp_reg=new_vsp_reg, new_vip_reg=new_vip_reg, new_vrk_reg=new_vrk_reg)
            print(f"After swap: VSP_REG: {state.vsp_reg} VIP_REG: {state.vip_reg} VRK_REG: {state.vrk_reg}")
            update_vip_direction(state, idx_mutation_end + 1, ic)

            return idx_mutation_end, pfx_ic
        else:
            return -1, None

    @classmethod
    def try_parse(cls, state: VMState, ic: InstructionCollection):
        idx, reloc_reg = cls._find_self_ref(state, 0, ic)

        if idx != -1:
            return cls.parse(state, ic)
        return -1, None


class VMHandlerParser:

    @classmethod
    def _all_parameters(cls, state: VMState, ic: InstructionCollection):
        cursor = 0
        while True:
            entity = next_parameter(state=state, cursor=cursor, ic=ic)
            if entity:
                yield entity
                cursor = entity.blk_end
            else:
                break

    @classmethod
    def parse(cls, state: VMState, ic: InstructionCollection):
        swap_end_idx, prefix_ic = VMSwapParser.try_parse(state, ic)
        if swap_end_idx != -1:
            ic = ic.tail_from(swap_end_idx + 1)

        values = list(cls._all_parameters(state, ic))
        o_ic = VMOptimizer.process(state, values, ic)
        if prefix_ic:
            o_ic = prefix_ic + o_ic

        if len(values) == 0:
            raise Exception("no values found")
        else:
            handler = VMHandler(rva=ic[0].address, parameters=values, ic=o_ic)
            VMArchitecture.classify(state, o_ic)

            return handler
