#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/random.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>
#include <errno.h>
#include "encrypt.h"



static const EVP_CIPHER *cipher_type; //  =  EVP_aes_256_gcm();


static const int AES_256_BLOCK_SIZE = 32;
#ifndef AES_BLOCK_SIZE
static const int AES_BLOCK_SIZE = 16;
#endif

static bool do_aes(bool encrypt, const int input_fd, const int output_fd, size_t optional_bytes, 
			const uint8_t aes_key[AES_256_BLOCK_SIZE],
			const uint8_t aes_iv[AES_BLOCK_SIZE])
{
	EVP_CIPHER_CTX *ctx;
	const int BUFSIZE = 8 * 1024;
	int cipher_block_size = EVP_CIPHER_block_size(cipher_type);
;
	uint8_t in_buf[BUFSIZE];
	uint8_t out_buf[BUFSIZE + cipher_block_size];
	int total_read = 0;

	ctx = EVP_CIPHER_CTX_new();
	if(!ctx) {
		fprintf(stderr, "Cannot create CTX\n");
		return false;
	}

	/* Don't set key or IV right away; we want to check lengths */
	if(!EVP_CipherInit_ex(ctx, cipher_type, NULL, NULL, NULL, encrypt)){
		fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

#if 0
	OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);
	OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_BLOCK_SIZE);
#endif
	/* Now we can set key and IV */
	if(!EVP_CipherInit_ex(ctx, NULL, NULL, aes_key, aes_iv, encrypt)){
		fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}
	
	write(output_fd,  aes_iv, AES_BLOCK_SIZE);
	

	while(1) {
		int bytes_read;
		int out_len;
		int result;

		if(optional_bytes > 0 && total_read >= optional_bytes)
			break;

		bytes_read = read(input_fd, in_buf, sizeof in_buf);
		if(!bytes_read) 
			break;

		if(bytes_read < 0) {
			fprintf(stderr, "problem reading file %s\n", strerror(errno));
			return false;
		}

		if(!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf,  bytes_read)) {
		     fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", 
				     ERR_error_string(ERR_get_error(), NULL));
		     return false;
		}
		result = write(output_fd, out_buf, out_len);
		if(result != out_len) {
			fprintf(stderr, "problem writing: wanted %d, wrote %d\n", out_len, result);
			abort();
		}
		total_read +=  bytes_read;
	}

	int out_len;

	if(!EVP_CipherFinal_ex(ctx, out_buf, &out_len)) {
		fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n", 
					ERR_error_string(ERR_get_error(), NULL));
		abort();
	}
	write(output_fd, out_buf, out_len);
	
	EVP_CIPHER_CTX_cleanup(ctx);
	return true;

}



bool do_encrypt(const char *input, const char *output, size_t bytes, const uint8_t key[AES_256_BLOCK_SIZE])
{
	int input_fd;
	int output_fd;
	int retval;
	bool result = false;	// default failure
	char iv[AES_BLOCK_SIZE];
	cipher_type = EVP_aes_256_gcm();
	


	input_fd = open(input, O_RDONLY);
	if(input_fd < 0) {
		fprintf(stderr, "cannot open input: %s: %s\n", input, strerror(errno));
		return false;
	}

	output_fd = open(output, O_WRONLY | O_CREAT, 0666);
	if(output_fd < 0) {
		fprintf(stderr, "cannot open output %s: %s\n", output, strerror(errno));
		close(input_fd);
		return false;
	}

	retval = getrandom(iv, sizeof iv, 0);
	if(retval < 0) {
		fprintf(stderr, "cannot get random iv: %s\n", strerror(errno));
		goto failure;
	}

	result = do_aes(true, input_fd, output_fd, bytes, key, iv);

failure:
	close(input_fd);
	close(output_fd);
	return result;

}


bool do_decrypt(const char *input, const char *output, const uint8_t key[AES_256_BLOCK_SIZE])
{
	return false;
}	

