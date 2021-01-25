/*
Template to run shellcodes
Place the shellcode in the code[] in hex format

 Compile: 
   gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
*/

#include <stdio.h>
#include <string.h>

unsigned char code[]= \
"";

void main()
{
        printf("ShellCode Lenght: %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
