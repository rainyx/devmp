import os
import sys

import capstone
import capstone as cs
import capstone.x86 as cs_x86
import unicorn as uc
import unicorn.x86_const as uc_x86
import lief

from entities import VMState, VMHandler, INVALID_RVA, VMBasicBlock
from subroutines import VMEntryParser, VMHandlerParser
from universal import X86Reg
from utils import imatch, InstructionCollection, Mod2NInt, get_shared_md, emulate_shared

vmp_bin_file_path = os.path.join(os.path.dirname(__file__), "vmtest.vmp.exe")


class VMP:

    def __init__(self, file_path):
        self.file_path = file_path
        self.binary = lief.PE.parse(file_path)
        self.sections = list(self.binary.sections)

    def _find_section(self, rva):
        sec = self.binary.section_from_rva(rva)
        off = self.binary.rva_to_offset(rva)
        assert sec and "Section not found"
        return sec

    def _is_vm_entry(self, rva):
        sec = self._find_section(rva)
        off = rva - sec.virtual_address
        # ----------------------------------------------------
        # push imm
        # call imm
        # ----------------------------------------------------
        return sec.content[off] == 0x68 and sec.content[off + 5] == 0xE8

    def _find_vm_entries(self) -> [int]:
        vm_entries = []
        md = get_shared_md()
        for sec in self.sections:
            if sec.name != ".text":
                continue

            rva = sec.virtual_address
            off = 0

            while off < sec.virtual_size:
                inst = next(md.disasm(sec.content[off:off + 15].tobytes(), rva))
                if imatch(inst, cs_x86.X86_INS_JMP, cs.CS_OP_IMM):
                    if inst.operands[0].type == cs.CS_OP_IMM:
                        jmp_rva = inst.operands[0].imm
                        if self._is_vm_entry(jmp_rva):
                            print(f"Found VMEntry at 0x{jmp_rva:x}")
                            vm_entries.append(jmp_rva)
                off += inst.size
                rva += inst.size
        return vm_entries

    def _deobfuscate(self, vm_handler_rva: int, debug=False) -> InstructionCollection:
        md = get_shared_md()
        sec = self._find_section(vm_handler_rva)

        insts = []
        off = vm_handler_rva - sec.virtual_address

        rip_rva = vm_handler_rva
        while rip_rva < sec.virtual_address + sec.virtual_size:
            off2 = min(off + 15, sec.offset + sec.size)
            inst = next(md.disasm(sec.content[off:off2].tobytes(), rip_rva))

            if imatch(inst, cs_x86.X86_INS_JMP, cs.CS_OP_IMM) \
                    or imatch(inst, cs_x86.X86_INS_CALL, cs.CS_OP_IMM):
                rip_rva = inst.operands[0].imm
                off = rip_rva - sec.virtual_address
            elif inst.id in [cs_x86.X86_INS_JMP, cs_x86.X86_INS_RET]:
                break
            else:
                if inst.id != cs_x86.X86_INS_NOP:
                    insts.append(inst)
                off += inst.size
                rip_rva += inst.size

        if debug:
            for idx in range(len(insts)):
                inst = insts[idx]
                print(f"[{idx:04d}] 0x{inst.address:08x} {inst.mnemonic} {inst.op_str}")

        return InstructionCollection(insts)

    def _trace_block(self, initial_state: VMState, vm_bb: VMBasicBlock):
        from utils import get_shared_ks
        image_base = self.binary.optional_header.imagebase
        ks = get_shared_ks()
        init_code = f"mov {initial_state.vsp_reg.name}, RSP\n" \
                    f"mov {initial_state.vip_reg.name}, 0x{initial_state.vip_rva + image_base:x}\n" \
                    f"mov {initial_state.vrk_reg.name}, 0x{initial_state.rolling_key:x}".encode('utf-8')

        code_bytes = bytes(ks.asm(init_code)[0])
        code_bytes = code_bytes + vm_bb.code_bytes

        vmp_sec = self.binary.section_from_rva(initial_state.vip_rva)

        stack_base = 0x0000000000000000
        stack_size = 2 * 1024 * 1024
        rsp = stack_base + int(stack_size / 2)

        mu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64)
        mu.mem_map(stack_base, stack_size)
        mu.reg_write(uc_x86.UC_X86_REG_RSP, rsp)

        insts = vm_bb.underlying_instructions
        inst_idx = 0

        def _hook_invalid_mem_access(mu, access, address, size, value, user_data):
            print(f"Invalid memory access: {access} address: 0x{address:08x} sz: {size} val: 0x{value:x}")

        def _hook_code64(_uc, address, size, user_data):
            nonlocal inst_idx
            if inst_idx < 3:
                inst_idx += 1
                return
            inst = insts[inst_idx-3]
            print(f" [{inst_idx}] [{_uc.reg_read(uc_x86.UC_X86_REG_RIP):x}] {inst}")
            for reg in [X86Reg.RSP, initial_state.vsp_reg]:
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

            inst_idx += 1

        mu.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED | uc.UC_HOOK_MEM_WRITE_UNMAPPED, _hook_invalid_mem_access)
        mu.hook_add(uc.UC_HOOK_CODE, _hook_code64)

        image_base = self.binary.optional_header.imagebase
        vmp_sec_va = image_base + vmp_sec.virtual_address

        mu.mem_map(vmp_sec_va, (vmp_sec.virtual_size // 0x100000 + 1) * 0x100000)
        mu.mem_write(vmp_sec_va, vmp_sec.content.tobytes())

        entry_va = image_base + vm_bb.entry_rva

        print(hex(entry_va))

        # mu.mem_map(code_base, code_size)
        mu.mem_write(entry_va, code_bytes)

        mu.emu_start(entry_va, entry_va + len(code_bytes))

        # VSP_REG: X86Reg.RSI
        # VSP_REG: X86Reg.RBX
        rsp = mu.mem_read(mu.reg_read(uc_x86.UC_X86_REG_RSI) - 8, 8)
        import struct
        print(hex(struct.unpack("<Q", rsp)[0]))

        return struct.unpack("<Q", rsp)[0] - image_base
        # print(code_bytes)

    def _unroll(self, state: VMState, handler_rva: int):
        vm_bb = VMBasicBlock()
        while True:
            print(f"Unroll 0x{handler_rva:x} VIP: 0x{state.vip_rva:x} VRK: 0x{state.rolling_key:x}")
            ic = self._deobfuscate(handler_rva, debug=False)
            handler = VMHandlerParser.try_parse(state, handler_rva, ic)
            vm_bb.add_handler(handler)

            handler_rva = handler.next_rva

    # def _unroll(self, state: VMState, handler_rva: int):
    #     initial_state = state.duplicate()
    #     vm_bb = VMBasicBlock()
    #     while True:
    #         print(f"Unroll 0x{handler_rva:x} VIP: 0x{state.vip_rva:x} VRK: 0x{state.rolling_key:x}")
    #         ic = self._deobfuscate(handler_rva, debug=False)
    #         handler = VMHandlerParser.parse(state, ic)
    #         vm_bb.add_handler(handler)
    #
    #         if handler.virtualized_instruction.op == "VJMP":
    #
    #             print("Found VJMP")
    #             next_vip = self._trace_block(initial_state, vm_bb)
    #             new_state = state.duplicate()
    #
    #             for p in handler.parameters:
    #                 print(p)
    #             new_state._vip_rva = next_vip
    #             new_state.update_rolling_key(self.binary.optional_header.imagebase + next_vip)
    #             jmp_off = new_state.read_vip(4)
    #
    #             db = handler.parameters[0]
    #             db._encrypted = jmp_off
    #             db._key = new_state.rolling_key
    #             db.decrypt(new_state)
    #
    #             handler_rva = Mod2NInt.normalize(state.reloc_rva + handler.next_rva, 32)
    #             print(hex(db.decrypted + state.reloc_rva))
    #             print(hex(db.decrypted))
    #             print(hex(state.rolling_key))
    #             break
    #         elif handler.next_rva != INVALID_RVA:
    #             handler_rva = handler.next_rva
    #             break
    #         else:
    #             break

    def _parse_vm_entry(self, vm_entry_rva):
        print(f"Processing VMEntry at 0x{vm_entry_rva:x}")
        ic = self._deobfuscate(vm_entry_rva)

        state, first_handler_rva = VMEntryParser.parse(self.binary, ic)
        first_handler_rva = 0xafaba
        state._vip_rva = 0x5972
        state._rolling_key = 0xfffffffffffe3ae2
        self._unroll(state, first_handler_rva)

    def process(self):
        vm_entries = self._find_vm_entries()
        for vm_entry_rva in vm_entries:
            self._parse_vm_entry(vm_entry_rva)


VMP(vmp_bin_file_path).process()
