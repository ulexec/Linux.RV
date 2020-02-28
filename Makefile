all:
	nasm -f elf32 rv.asm
	ld rv.o -o rv
	gcc test.c -o test
clean:
	rm ./*.o
