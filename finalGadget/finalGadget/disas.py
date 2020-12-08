# disas.py

from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

class Disas:
        def __init__(self, filepath):
                self.__filename = filepath 
        def disassemble(self):
                disas = [] #list of tuples: tup[0] = address, tup[1] = instruction, tup[2] = args
                print(self.__filename)
                with open(self.__filename, 'rb') as file:
                        elf = ELFFile(file)
                        code = elf.get_section_by_name('.text')
                        ops = code.data()
                        addr = code['sh_addr']
                        md = Cs(CS_ARCH_X86, CS_MODE_64)
                        for i in md.disasm(ops,addr):
                                #print(f'0x{i.address:x}\t{i.mnemonic}\t{i.op_str}')
                                disas.append((i.address,i.mnemonic,i.op_str))
                        for section in elf.iter_sections():
                                if isinstance(section, RelocationSection):
                                        print(f'{section.name}:')
                                        symbol_table = elf.get_section(section['sh_link'])
                                        for relocation in section.iter_relocations():
                                                symbol = symbol_table.get_symbol(relocation['r_info_sym'])
                                                addr = hex(relocation['r_offset'])
                                                print(f'{symbol.name} {addr}')
                gadgets = []
                gadgetIndex = 0
                while gadgetIndex < len(disas):
                        if (disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+1][1] == 'ret'):
                                gadgets.append((disas[gadgetIndex],disas[gadgetIndex+1]))
                        gadgetIndex = gadgetIndex + 1
                print(gadgets)

