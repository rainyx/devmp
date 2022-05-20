from typing import NoReturn, Optional

import capstone as cs
import capstone.x86 as cs_x86
from lief.PE import Binary

from entities import VMState, VMHandler, VIPDirection, VMDecryptionBlock, VMDecryptedInfo, VMBasicBlock
from execution import VMBranchAnalyzer
from instructions import VMInstructions
from optimizers import VMInstructionsOptimizer
from universal import X86Reg
from utils import InstructionCollection, LinkedList, xor_sized, imatch, Mod2NInt, emulate_shared


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
                    return False

                last_mapping[from_reg].append(to_reg)
                last_mapping[to_reg] = last_mapping[from_reg]
                return True

            def _exchange(reg_a: X86Reg, reg_b: X86Reg):
                if reg_a not in last_mapping or reg_b not in last_mapping:
                    # junk mapping
                    return False

                last_mapping[reg_b].append(reg_a)
                last_mapping[reg_a].append(reg_b)

                tmp_chain = last_mapping[reg_a]
                last_mapping[reg_a] = last_mapping[reg_b]
                last_mapping[reg_b] = tmp_chain
                return True

            prefix_end_idx = None
            for inst_idx in range(1, idx_mutation_end):
                inst = ic[inst_idx]

                if len(inst.operands) != 2 or inst.operands[0].size != 8:
                    continue

                changed = False
                if imatch(inst, cs_x86.X86_INS_MOV, cs.CS_OP_REG, cs.CS_OP_REG):
                    r1 = X86Reg.from_capstone(inst.operands[0].reg)
                    r2 = X86Reg.from_capstone(inst.operands[1].reg)
                    changed = _map(from_reg=r2, to_reg=r1)
                elif imatch(inst, cs_x86.X86_INS_XCHG, cs.CS_OP_REG, cs.CS_OP_REG):
                    r1 = X86Reg.from_capstone(inst.operands[0].reg)
                    r2 = X86Reg.from_capstone(inst.operands[1].reg)
                    changed = _exchange(reg_a=r1, reg_b=r2)

                if prefix_end_idx is None and changed:
                    prefix_end_idx = inst_idx - 1

            for chain in mapping_chains:
                # print(f"Last: {reg}")
                print("new mapping chain: ")
                node = chain.head
                while node:
                    print("  ", node.value)
                    node = node.next

            new_vrk_reg_node = vip_chain.tail
            new_vip_reg_node = new_vrk_reg_node.prev
            new_vsp_reg_node = vsp_chain.tail

            prefix_ic = ic.range_of(1, prefix_end_idx)
            prefix_ic = VMInstructionsOptimizer.process(state, [], prefix_ic)
            # for i in prefix_ic:
            #     print("prefix", i)
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
        if not d_blks:
            print("VMExit")
            return None

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
            next_vip = branches[0]
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
