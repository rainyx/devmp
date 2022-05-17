import os
import sys

import capstone
import capstone as cs
import capstone.x86 as cs_x86
import unicorn as uc
import unicorn.x86_const as uc_x86
import lief

from entities import VMState, VMHandler, INVALID_RVA, VMBasicBlock, VIPDirection
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

    def _unroll(self, state: VMState, handler_rva: int):
        initial_state = state.duplicate()
        vm_bb = VMBasicBlock()
        while True:
            # print(f"Unroll 0x{handler_rva:x}, VIP: 0x{state.vip_rva:x}, VRK: 0x{state.rolling_key:x}, "
            #       f"VIP_REG: {state.vip_reg}, VSP_REG: {state.vsp_reg}, VRK_REG: {state.vrk_reg}")
            ic = self._deobfuscate(handler_rva, debug=False)
            handler = VMHandlerParser.try_parse(state, handler_rva, initial_state, vm_bb, ic)

            if handler.virtualized_instruction.op == 'VJMP':
                self._unroll(state, handler.next_rva)
                break
            else:
                handler_rva = handler.next_rva

    def _parse_vm_entry(self, vm_entry_rva):
        print(f"Processing VMEntry at 0x{vm_entry_rva:x}")
        ic = self._deobfuscate(vm_entry_rva)

        state, first_handler_rva = VMEntryParser.parse(self.binary, ic)

        # state = VMState(binary=self.binary,
        #                 vsp_reg=X86Reg.RBX,
        #                 vip_reg=X86Reg.R9,
        #                 vrk_reg=X86Reg.RDI,
        #                 vip_rva=0x5e2a,
        #                 rolling_key=0xfff437b6,
        #                 reloc_rva=INVALID_RVA,
        #                 vip_direction=VIPDirection.BACKWARD)
        # first_handler_rva = 0xd896a
        # state = VMState(binary=self.binary,
        #                 vsp_reg=X86Reg.RBX,
        #                 vip_reg=X86Reg.R9,
        #                 vrk_reg=X86Reg.RDI,
        #                 vip_rva=0x5c74,
        #                 rolling_key=0xfffffffffff16f8a,
        #                 reloc_rva=INVALID_RVA,
        #                 vip_direction=VIPDirection.BACKWARD)
        # first_handler_rva = 0x1529a
        self._unroll(state, first_handler_rva)

    def process(self):
        vm_entries = self._find_vm_entries()
        for vm_entry_rva in vm_entries:
            self._parse_vm_entry(vm_entry_rva)


VMP(vmp_bin_file_path).process()
