/*
  This is the msfvnom shellcode for the payload linux/x64/exec

  Generated with command:
        msfvenom -p linux/x64/exec CMD="/bin/ls -l" -f c
*/

/*
  ASM

0000000000004060 <code>:
    4060:       6a 3b                   push   0x3b
    4062:       58                      pop    rax
    4063:       99                      cdq
    4064:       48 bb 2f 62 69 6e 2f    movabs rbx,0x68732f6e69622f
    406b:       73 68 00
    406e:       53                      push   rbx
    406f:       48 89 e7                mov    rdi,rsp
    4072:       68 2d 63 00 00          push   0x632d
    4077:       48 89 e6                mov    rsi,rsp
    407a:       52                      push   rdx
    407b:       e8 0b 00 00 00          call   408b <code+0x2b>
    4080:       2f                      (bad)
    4081:       62                      (bad)
    4082:       69 6e 2f 6c 73 20 2d    imul   ebp,DWORD PTR [rsi+0x2f],0x2d20736c
    4089:       6c                      ins    BYTE PTR es:[rdi],dx
    408a:       00 56 57                add    BYTE PTR [rsi+0x57],dl
    408d:       48 89 e6                mov    rsi,rsp
    4090:       0f 05                   syscall
        ...

*/

#include <stdio.h>
#include <string.h>

unsigned char code[]= \
"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53"
"\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8\x0b\x00"
"\x00\x00\x2f\x62\x69\x6e\x2f\x6c\x73\x20\x2d\x6c\x00\x56\x57"
"\x48\x89\xe6\x0f\x05";

void main()
{
        printf("ShellCode Lenght: %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}

