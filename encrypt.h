#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#include <stdbool.h>
/* open, encrypt the files with the selected key.    Use a random IV (in the first 16 bytes of output
 * optional_size is useful if input_file is /dev/zero (how many bytes to encrypt), otherwise do
 * input_file until EOF (if optional_size == 0)
 */
bool do_encrypt(const char *input_file, const char *output_file, size_t optional_size, const uint8_t key_256[32]);

bool do_decrypt(const char *input_file, const char *output_file, const uint8_t key_256[32]);

enum cipher_type {
	AES_256_GCM,
	AES_256_CBC,
	AES_256_CTR
};


enum encrypt_result {
	ENCRYPT_SUCESSFUL,
	ENCRYPT_WRITE_FAILED

	
};

enum decreypt_result {
	DECRYPT_SUCCESSFUL
};


void select_cipher_type(enum cipher_type type);

#endif
