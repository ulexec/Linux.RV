all:
	nasm -f elf32 rv.asm
	ld rv.o -o rv

clean:
	rm ./*.o
