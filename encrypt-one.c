#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "encrypt.h"


// static const uint8_t key[32] =  { "abcdefghij"  "klmnopqrst" "ABCDEFGHIJK" };

static const uint8_t key[32] = { 0 };

int main(int argc, char *argv[])
{
	if(argc != 3) {
		printf("wrong number of args\n");
		exit(1)	;
	}

//	select_cipher_type(AES_256_CBC);
	do_encrypt(argv[1], argv[2], 0, key);
}


