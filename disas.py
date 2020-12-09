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

gadgets = []
gadgetIndex = 0
while gadgetIndex < len(disas):
        '''if (disas[gadgetIndex][1] == 'ret'):
                gadgets.append((disas[gadgetIndex],))'''
        if (disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+1][1] == 'ret'):
                gadgets.append((disas[gadgetIndex],disas[gadgetIndex+1]))
        if ((disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+1][1] == 'pop') and (disas[gadgetIndex+2][1] == 'ret')):
                gadgets.append((disas[gadgetIndex],disas[gadgetIndex+1],disas[gadgetIndex+2]))
        if ((disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+1][1] == 'pop') and (disas[gadgetIndex+2][1] == 'pop') and (disas[gadgetIndex+3][1] == 'ret')):
                gadgets.append((disas[gadgetIndex],disas[gadgetIndex+1],disas[gadgetIndex+2],disas[gadgetIndex+3]))
        if ((disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+1][1] == 'pop') and (disas[gadgetIndex+2][1] == 'pop') and (disas[gadgetIndex+3][1] == 'pop') and (disas[gadgetIndex+4][1] == 'ret')):
                gadgets.append((disas[gadgetIndex],disas[gadgetIndex+1],disas[gadgetIndex+2],disas[gadgetIndex+3],disas[gadgetIndex+4]))
        if ((disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+1][1] == 'pop') and (disas[gadgetIndex+2][1] == 'pop') and (disas[gadgetIndex+3][1] == 'pop') and (disas[gadgetIndex+4][1] == 'pop') and (disas[gadgetIndex+5][1] == 'ret')):
                gadgets.append((disas[gadgetIndex],disas[gadgetIndex+1],disas[gadgetIndex+2],disas[gadgetIndex+3],disas[gadgetIndex+4],disas[gadgetIndex+5]))


        gadgetIndex = gadgetIndex + 1

#remove duplicates
gadgets.sort()
gadgetIndex = 1
while gadgetIndex < len(gadgets):
        #if lengths are different, gadgets must be different
        if len(gadgets[gadgetIndex]) != len(gadgets[gadgetIndex-1]):
                gadgetIndex+=1
                continue
        gadgetIndex2 = 0
        broke = False
        while gadgetIndex2 < (len(gadgets[gadgetIndex])-1):
                #if args of instructions are different, gadgets must be different
                if gadgets[gadgetIndex][gadgetIndex2][2] != gadgets[gadgetIndex-1][gadgetIndex2][2]:
                        gadgetIndex += 1
                        broke = True
                        break
                gadgetIndex2 += 1
        if(not broke):
                del gadgets[gadgetIndex]

for i in gadgets:
        print(i)
