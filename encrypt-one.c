#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include "encrypt.h"
#include "buffer_manager.h"


// static const uint8_t key[32] =  { "abcdefghij"  "klmnopqrst" "ABCDEFGHIJK" };

static const uint8_t key[32] = { 0 };

int main(int argc, char *argv[])
{
	int num_buffers = 1;
	int buffer_size = 1024 * 16;
	char *input_file;
	char *output_file;

	while(1) {
		int c;

		c = getopt(argc, argv, "b:n:");
		if(-1 == c)
			break;
		switch(c) {
			case 'b':
				buffer_size = strtol(optarg, NULL, 10);
				break;
			case 'n':
				num_buffers = strtol(optarg, NULL, 10);
				break;
			default:
				break;
		}
	}


	if(optind + 2 != argc) {
		printf("wrong args\n");
		exit(1);
	}

	input_file = strdup(argv[optind]);
	output_file = strdup(argv[optind + 1]);

	create_buffers(buffer_size, num_buffers);

	
//	select_cipher_type(AES_256_CBC);
	do_encrypt(input_file, output_file, 0, key);
	destroy_buffers();
}


