import sys
from elftools.elf.elffile import ELFFile
from capstone import *
from finalGadget.disas import Disas

def elfBinChecker(fileName):
	return True
	'''
	Continued to print Invalid File Typle for vuln_prog2.bin ...

	try:
		with open(fileName, 'rb') as f:
			elf = ELFFile(f)
			code = elf.get_section_by_name('.text')
			ops = code.data()
			addr = code['sh_addr']
			md = Cs(CS_ARCH_X86, CS_MODE_64)
			return True
	except:
		print("Invalid file type")
		return False
	
	Return true assuming we only give the program elfBins and wont break usage cases
	'''

def main():
	if len(sys.argv) < 2:
		print("Usage 1: finaglGadget.py <ELF BIN 1> <MORE ELF BINS> <...>")
		sys.exit(1)
	argInd = 1
	while argInd < len(sys.argv):
		if elfBinChecker(sys.argv[argInd]) == False:
			print("Usage 2: finaglGadget.py <ELF BIN 1> <MORE ELF BINS> <...>")
			sys.exit(1)
		else:
			argInd += 1
	while argInd > 1:
		temp = Disas(sys.argv[argInd-1])
		print(Disas.disassemble(temp))
		argInd = argInd-1
	sys.exit(0)

if "__name__" == "__main__":
	main()