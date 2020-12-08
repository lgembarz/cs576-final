# disas.py

from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
filename= './vuln_prog1.bin'
with open(filename, 'rb') as file:
        elf = ELFFile(file)
        code = elf.get_section_by_name('.text')
        ops = code.data()
        addr = code['sh_addr']
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(ops,addr):
                print(f'0x{i.address:x}\t{i.mnemonic}\t{i.op_str}')
        for section in elf.iter_sections():
                if isinstance(section, RelocationSection):
                        print(f'{section.name}:')
                        symbol_table = elf.get_section(section['sh_link'])
                        for relocation in section.iter_relocations():
                                symbol = symbol_table.get_symbol(relocation['r_info_sym'])
                                addr = hex(relocation['r_offset'])
                                print(f'{symbol.name} {addr}')
