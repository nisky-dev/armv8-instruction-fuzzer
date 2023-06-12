#note you need to install capstone first, compile latest binutils from source and run sudo make install (goes to /usr/include/lib)
#if you can't use sudo, manually copying the libopcodes.a and libbfd.a files from the binutils directory and linking them should work (use second version of disassembler make rule)

CC = gcc #TODO amend as needed, on Arm platforms this is ovc just gcc

all: clean opcodeTester disasm

debug:
	gcc -g -O0 -o opcodetester opcodeTester.c -lcapstone -L/usr/local/lib -lopcodes -lbfd -liberty -lz -ldl


opcodeTester:
	gcc -static -o opcodetester opcodeTester.c disassembler.c -L/usr/local/lib -lopcodes -lbfd -liberty -lz -ldl

disasm:
	gcc -ggdb -o disasm disassembler.c -L/usr/local/lib -lopcodes -lbfd -liberty -lz -ldl
	#gcc -ggdb -o disasm disassembler.c -L/usr/local/lib -lopcodes -I:./binutils-2.33.90/ld/ -I:./binutils-2.33.90/opcodes/libopcode.a -I:./binutils-2.33.90/bfd/bfd.a -I:./binutils-2.33.90/libiberty/libiberty.a -I:./binutils-2.33.90/zlib/zlib.a

cucheck:
	gcc -o cucheck cu_check.c


clean:
	rm -f opcodetester disasm

