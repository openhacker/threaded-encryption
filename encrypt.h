#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#include <stdbool.h>

enum cipher_type {
	AES_256_GCM,
	AES_256_CBC,
	AES_256_CTR
};


enum encrypt_result {
	ENCRYPT_SUCCESSFUL,
	ENCRYPT_NO_CTX,
	ENCRYPT_GET_PARAMS_FAILED,
	ENCRYPT_WRITE_FAILED,
	ENCRYPT_READ_PROBLEM,
	ENCRYPT_UPDATE_FAILED,
	ENCRYPT_CANNOT_OPEN_INPUT,
	ENCRYPT_CANNOT_OPEN_OUTPUT,
	ENCRYPT_CANNOT_COMPUTE_SHA256,
	ENCRYPT_FINAL_FAILED,
	ENCRYPT_FAILURE

	
	
};

enum decreypt_result {
	DECRYPT_SUCCESSFUL
};


/* open, encrypt the files with the selected key.    Use a random IV (in the first 16 bytes of output
 * optional_size is useful if input_file is /dev/zero (how many bytes to encrypt), otherwise do
 * input_file until EOF (if optional_size == 0)
 */
enum encrypt_result do_encrypt(const char *input_file, const char *output_file, size_t optional_size, const uint8_t key_256[32]);

bool do_decrypt(const char *input_file, const char *output_file, const uint8_t key_256[32]);

void select_cipher_type(enum cipher_type type);

#endif
