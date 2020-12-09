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
        if (disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+1][1] == 'ret'):
                gadgets.append((disas[gadgetIndex],disas[gadgetIndex+1]))
        if ((disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+1][1] == 'pop') and (disas[gadgetIndex+2][1] == 'ret')):
                gadgets.append((disas[gadgetIndex],disas[gadgetIndex+1],disas[gadgetIndex+2]))

        gadgetIndex = gadgetIndex + 1

'''
for reg_tup in register_tuple:
    for x in range(0, len(gadgets)):
        if (gadgets[x][2] == reg_tup[1]) and (gadgets[x][1] < reg_tup[2]):
            reg_tup[2] = gadgets[x][1]
'''


'''
while gadgetIndex < len(disas):
    for distance_to_ret in range(1,6):
        for reg in [("rdi", "rsi", "rdx"]:
            if (disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+distance_to_ret][1] == 'ret'):
                gadgets.append((disas[gadgetIndex],disas[gadgetIndex+1]))


    gadgetIndex = gadgetIndex + 1
'''

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

shortest_rdi = 100
shortest_rsi = 100
shortest_rdx = 100

for x in range(0, len(gadgets)):
    if (gadgets[x][0][2] == "rdi") and (len(gadgets[x]) < shortest_rdi):
        shortest_rdi = len(gadgets[x])
    elif (gadgets[x][0][2] == "rsi") and (len(gadgets[x]) < shortest_rsi):
        shortest_rsi = len(gadgets[x])
    elif (gadgets[x][0][2] == "rdx") and (len(gadgets[x]) < shortest_rdx):
        shortest_rdx = len(gadgets[x])
    else:
        print("uhoh")

print(shortest_rdi)
print(shortest_rsi)
print(shortest_rdx)

