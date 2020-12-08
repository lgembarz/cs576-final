import sys
from elftools.elf.elffile import ELFFile
from capstone import *

def main():
	if len(sys.argv) < 2:
    		print("Usage: finaglGadget.py <ELF BIN 1> <MORE ELF BINS> <...>")
    		sys.exit(1)
	def elfBinChecker(fileName):
		try:
			with open(fileName, 'rb') as f:
				elf = ELFFile(f)
				code = elf.get_section_by_name('.text')
				ops = code.data()
				addr = code['sh_addr']
				md = Cs(CS_ARCH_X86, CS_MODE_64)
				for i in md.disasm(ops, addr):        
					print(f'0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}')
			return True
		except IOError:
			print("Invalid file type")
			return False
	elfBins = 2
 	while elfBins < len(sys.argv):
		if elfBinChecker(argv[elfBins]) :
	    		continue
	    	else :
	    		print("Usage: finaglGadget.py <ELF BIN 1> <MORE ELF BINS> <...>")
	    		sys.exit(1)
	sys.exit(0)

if__name__ == "__main__":
	main()
    
# assuming all inputs are elf binaries, run them through the parser



    '''str = ""
while True :
	# execute the string in the vulnerable binary
	# if stack smashing detected 
		return str.length()
	else :
		str += "A"'''
    

