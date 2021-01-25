/*
  Author: Guillem Alminyana
  
  Checks a shellcode for it's size and NULLs.
  Prints the total of NULLs and position where is found
  
  Place the shellcode to check in code[]
  
  Compile: gcc file.c -o file
  
*/

#include <stdio.h>
#include <strings.h>

unsigned char code[]= \
"";


int main (int argc, char *argv[])
{
        printf("\nShellCode Lenght (NULLs included): %d\n", sizeof(code)-1);

        int count = 0;

        printf("Checking for NULLs on the shellcode...\n");

        for (int i=0; i<sizeof(code)-1; i++)    // -1 as last is the end string NULL
        {
                if (code[i] == '\x00') {
                        count++;
                        printf("   NULL found at %d\n", i);
                }

        }

        printf("Nulls in Shellcode: %d\n", count);
}
