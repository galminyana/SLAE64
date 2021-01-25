; Author: Guillem Alminyana
;
; Reads input, stores it, and then prints the string
; 
; Just an example of how to use syscalls
; 
; Uses syscalls:
;	- sys_write
;	- sys_read
;
; Compile:
;	nasm -f elf64 file.nasm -o file.o
;	ld -N file.o -o file
; Test:
;	run ./file
;	connect from another terminal with nc localhost 4444
;

global _start			

section .text
_start:

	; READ
	; Read up to 8 characters
	mov rax, 0	; Syscall Number
	mov rdi, 0
	lea rsi, [Input]
	mov rdx, 8
	syscall
	nop

	; WRITE
	; Print the input
  mov rax, 1
  mov rdi,1
  mov rsi, Input
  mov rdx, len_Input
  syscall

	; EXIT
	mov rax, 0x3c
	mov rdi, 0
	syscall

section .data

	Password:	db	"asdfqwer"
	len:	equ	$-Password

section .bss

	Input:	resb	len
	len_Input:	resb	8

