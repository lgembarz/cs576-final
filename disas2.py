import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from capstone import *


def elfBinChecker(fileName):
    try:
        filename = fileName
        disas = []  # list of tuples: tup[0] = address, tup[1] = instruction, tup[2] = args
        with open(filename, 'rb') as file:
            elf = ELFFile(file)
            code = elf.get_section_by_name('.text')
            ops = code.data()
            addr = code['sh_addr']
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            for i in md.disasm(ops, addr):
                print(f'0x{i.address:x}\t{i.mnemonic}\t{i.op_str}')
                disas.append((i.address, i.mnemonic, i.op_str))
            for section in elf.iter_sections():
                if isinstance(section, RelocationSection):
                    print(f'{section.name}:')
                    symbol_table = elf.get_section(section['sh_link'])
                    for relocation in section.iter_relocations():
                        symbol = symbol_table.get_symbol(
                            relocation['r_info_sym'])
                        addr = hex(relocation['r_offset'])
                        print(f'{symbol.name} {addr}')
        gadgets = []
        gadgetIndex = 0
        while gadgetIndex < len(disas):
            if (disas[gadgetIndex][1] == 'pop') and (disas[gadgetIndex+1][1] == 'ret'):
                gadgets.append((disas[gadgetIndex], disas[gadgetIndex+1]))
            gadgetIndex = gadgetIndex + 1
        print(gadgets)
    except IOError:
        print("Invalid file type")
        return False


def main():
    '''lenArgs = len(sys.argv)
    if lenArgs< 2:
            print("Usage 1: finaglGadget.py <ELF BIN 1> <MORE ELF BINS> <...>")
            sys.exit(1)
    elfBins = 1
    while elfBins < lenArgs:
            if elfBinChecker(lenArgs) == False:
                    print("Usage: finaglGadget.py <ELF BIN 1> <MORE ELF BINS> <...>")
                    sys.exit(1)'''
    elfBinChecker(sys.argv[1])
    '''except:
		print("Usage 2: finaglGadget.py <ELF BIN 1> <MORE ELF BINS> <...>")
		sys.exit(1)
		else:
			elfBins = elfBins + 1'''
    print("andddd made it here")
    sys.exit(0)


if __name__ == "__main__":
    main()

