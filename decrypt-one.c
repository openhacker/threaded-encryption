#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "encrypt.h"


static const char key[32] =  { "abcdefghij"  "klmnopqrst" "ABCDEFGHIJK" };

main(int argc, char *argv[])
{
	if(argc != 3) {
		printf("wrong number of args\n");
		exit(1)	;
	}

	do_decrypt(argv[1], argv[2], key);
}


