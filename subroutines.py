import capstone as cs
import capstone.x86 as cs_x86
import unicorn as uc
import unicorn.x86_const as uc_x86
from lief.PE import Binary

from instructions import VMInstructions
from utils import InstructionCollection, xor_sized, imatch, Mod2NInt, emulate_shared, get_shared_ks
from universal import X86Reg
from entities import VMState, VMHandler, VIPDirection, VMDecryptionBlock, VMDecryptedInfo, VMBasicBlock
from optimizers import VMInstructionsOptimizer

import struct as st


class VMTracer:

    def _hook_invalid_mem(self, mu, access, address, size, value, user_data):
        print(f"Invalid memory access: {access} address: 0x{address:08x} sz: {size} val: 0x{value:x}")

    def _hook_code(self, _uc, address, size, user_data):
        if self._current_inst_idx < 3:
            self._current_inst_idx += 1
            return
        inst = self._current_insts[self._current_inst_idx - 3]
        print(f" [{self._current_inst_idx}] [{_uc.reg_read(uc_x86.UC_X86_REG_RIP):x}] {inst}")
        for reg in [X86Reg.RSP, self._current_state.vsp_reg]:
            print(f"    {reg}: 0x{_uc.reg_read(reg.unicorn):x}")
        reg_uses, reg_defs = inst.regs_access()
        if reg_uses:
            print("    ==== reg uses:")
            for reg in reg_uses:
                u_reg = X86Reg.from_capstone(reg)
                print(f"    {u_reg}: 0x{_uc.reg_read(u_reg.unicorn):x}")

        if reg_defs:
            print("    ==== reg defs:")
            for reg in reg_defs:
                u_reg = X86Reg.from_capstone(reg)
                print(f"    {u_reg}")

        self._current_inst_idx += 1

    def __init__(self, binary: Binary):
        stack_base = 0xF000000000000000
        stack_size = 2 * 1024 * 1024
        rsp = stack_base + int(stack_size / 2)

        mu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64)

        # mu.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED | uc.UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_invalid_mem)
        # mu.hook_add(uc.UC_HOOK_CODE, self._hook_code)

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

    @property
    def emulator(self) -> uc.Uc:
        return self._mu

    @property
    def binary(self) -> Binary:
        return self._binary

    def trace(self, initial_state: VMState, vm_bb: VMBasicBlock):
        self._current_state = initial_state
        image_base = self.binary.optional_header.imagebase

        ks = get_shared_ks()
        # create trace code
        init_code = f"mov {initial_state.vsp_reg.name}, RSP\n" \
                    f"mov {initial_state.vip_reg.name}, 0x{initial_state.vip_rva + image_base:x}\n" \
                    f"mov {initial_state.vrk_reg.name}, 0x{initial_state.rolling_key:x}".encode('utf-8')

        code_bytes = bytes(ks.asm(init_code)[0])
        code_bytes = code_bytes + vm_bb.code_bytes

        insts = vm_bb.underlying_instructions
        self._current_insts = insts
        self._current_inst_idx = 0

        entry_va = image_base + vm_bb.entry_rva

        print("EntryVA", hex(entry_va))
        # write trace code and execute
        mu = self.emulator
        mu.mem_write(entry_va, code_bytes)
        mu.emu_start(entry_va, entry_va + len(code_bytes))

        # retrieve trace results
        # VSP_REG: X86Reg.RSI
        # VSP_REG: X86Reg.RBX
        rsp = mu.mem_read(mu.reg_read(initial_state.vsp_reg.unicorn), 8)
        print("NEW", hex(st.unpack("<Q", rsp)[0]))

        return st.unpack("<Q", rsp)[0] - image_base


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

    vip_dir = VIPDirection.UNSPECIFIED
    if forward_idx != -1:
        vip_dir = VIPDirection.FORWARD
    elif backward_idx != -1:
        vip_dir = VIPDirection.BACKWARD
    else:
        raise Exception("vip direction not determined")

    state.update_vip_direction(vip_dir)


def _decrypt(state: VMState, decryption_block: VMDecryptionBlock) -> VMDecryptedInfo:
    encrypted = state.read_vip(decryption_block.value_size)
    code_bytes = decryption_block.transforms.get_all_bytes()

    encrypted = xor_sized(encrypted, state.rolling_key, decryption_block.value_size)
    # print(f"  {encrypted_val:x}, {state.rolling_key:x}")

    out_reg_values = emulate_shared(code_bytes, {
        state.vrk_reg: state.rolling_key, decryption_block.def_reg: encrypted
    }, [decryption_block.def_reg, state.vrk_reg])

    decrypted = out_reg_values[decryption_block.def_reg]
    # print(f"decrypted_val:  {decrypted_val:x}")
    # update rolling key
    next_key = xor_sized(state.rolling_key, decrypted, decryption_block.value_size)
    state.update_rolling_key(next_key)

    d_info = VMDecryptedInfo(i_begin_index=decryption_block.i_begin_index, i_end_index=decryption_block.i_end_index,
                             def_reg=decryption_block.def_reg, value_size=decryption_block.value_size, value=decrypted)

    return d_info


def _next_decryption_block(state: VMState, cursor: int, ic: InstructionCollection):
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

    trans_ic, _ = ic.trace(def_reg.extended, begin_idx + 1, end_idx - 1)

    if imatch(ic[end_idx], cs.x86.X86_INS_XOR, cs.CS_OP_MEM, cs.x86.X86_OP_REG):
        def _pop_finder2(i):
            return imatch(i, cs.x86.X86_INS_POP, cs.x86.X86_OP_REG) and \
                   state.vrk_reg.is_equal_to_capstone(i.operands[0].reg)

        end_idx = ic.next_index_by(end_idx, _pop_finder2)

    block = VMDecryptionBlock(i_begin_index=begin_idx, i_end_index=end_idx, def_reg=def_reg, value_size=value_size,
                              transforms=trans_ic)

    return block


def _next_decrypted(state: VMState, cursor: int, ic: InstructionCollection):
    d_blk = _next_decryption_block(state, cursor, ic)
    if d_blk is None:
        return -1, None

    info = _decrypt(state, d_blk)
    return info


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
    def _find_self_ref(cls, state: VMState, ic: InstructionCollection):
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
    def try_parse(cls, state: VMState, ic: InstructionCollection):
        reloc_rva = cls._find_self_ref(state, ic)
        if reloc_rva is None:
            return None

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
            pfx_ic = VMInstructionsOptimizer.process(state, [], pfx_ic)

            print(f"Before swap: VSP_REG: {state.vsp_reg} VIP_REG: {state.vip_reg} VRK_REG: {state.vrk_reg}")
            state.swap(new_vsp_reg=new_vsp_reg, new_vip_reg=new_vip_reg, new_vrk_reg=new_vrk_reg)
            print(f"After swap: VSP_REG: {state.vsp_reg} VIP_REG: {state.vip_reg} VRK_REG: {state.vrk_reg}")
            update_vip_direction(state, idx_mutation_end + 1, ic)

            return cls.Result(reloc_rva=reloc_rva, i_end_index=idx_mutation_end, prefix_ic=pfx_ic)
        else:
            return None


class VMHandlerParser:

    @classmethod
    def _all_decryption_blocks(cls, state: VMState, ic: InstructionCollection):
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

        # decrypt all operands
        for op_idx in range(len(d_blks) - 1):
            d_info = _decrypt(state, d_blks[op_idx])
            d_operand_infos.append(d_info)
            operands.append(d_info.value)
            # print(f"{op_idx}, 0x{d_info.value:x}")

        # Discard calc_jmp_off routine
        ic = ic.head(last_d_bkl.i_begin_index)
        ic = VMInstructionsOptimizer.process(state, d_operand_infos, ic)
        if swap:
            ic = swap.prefix_ic + ic
        v_inst = VMInstructions.classify(state, ic)

        if v_inst.op == 'VJMP':
            print('VJMP hit')
            tracer = VMTracer(state.binary)
            next_vip = tracer.trace(initial_state, vm_basic_block)
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
        return handler
