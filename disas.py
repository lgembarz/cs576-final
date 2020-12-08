# disas.py

from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
filename= './vuln_prog2.bin'
disas = [] #list of tuples: tup[0] = address, tup[1] = instruction, tup[2] = args
with open(filename, 'rb') as file:
        elf = ELFFile(file)
        code = elf.get_section_by_name('.text')
        ops = code.data() # type bytes
        # ops2 = ops[-15:]
        addr = code['sh_addr'] # type int
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        # gets all instructions, intended or not

        while(ops != b""):
            for i in md.disasm(ops, addr):
                disas.append((i.address,i.mnemonic,i.op_str))
            addr += 1
            ops = ops[1:]


'''
gadgets = []
gadgetIndex = 0
while gadgetIndex < len(disas):
        if (disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+1][1] == 'ret'):
                gadgets.append((disas[gadgetIndex],disas[gadgetIndex+1]))
        gadgetIndex = gadgetIndex + 1
for i in gadgets:
        print(i)
        #print('\n')
'''

