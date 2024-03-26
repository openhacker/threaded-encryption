#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/random.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <string.h>
#include <errno.h>
#include "encrypt.h"



static const EVP_CIPHER *cipher_type; //  =  EVP_aes_256_gcm();
static bool authenticated = false;	// depends on the cipher type 
static enum cipher_type enum_cipher;


static const int AES_256_BLOCK_SIZE = 32;
#ifndef AES_BLOCK_SIZE
static const int AES_BLOCK_SIZE = 16;
#endif


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


/* from demos/cipher/aesgcm.c */
static bool aes_gcm_encrypt(int input_fd, int output_fd, 
			int optional_bytes, 
			unsigned char *aad, int aad_len,
			unsigned char *gcm_key, 	/* 32 chars */
			unsigned char *gcm_iv, size_t iv_len)
{

   bool ret = false;
    EVP_CIPHER_CTX *ctx;
    unsigned char temp_buf[1024];
    int tmplen;
//    int outlen, tmplen;
 //   size_t gcm_ivlen = sizeof(gcm_iv);
    unsigned char outtag[16];
    OSSL_PARAM params[2] = {
        OSSL_PARAM_END, OSSL_PARAM_END
    };
    size_t cipher_block_size = EVP_CIPHER_block_size(cipher_type);
    size_t total_bytes_read = 0;


    /* Create a context for the encrypt operation */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

#if 0
    /* Fetch the cipher implementation */
    if ((cipher = EVP_CIPHER_fetch(libctx, "AES-256-GCM", propq)) == NULL)
        goto err;
#endif

    /* Set IV length if default 96 bits is not appropriate */
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &iv_len);

    /*
     * Initialise an encrypt operation with the cipher/mode, key, IV and
     * IV length parameter.
     * For demonstration purposes the IV is being set here. In a compliant
     * application the IV would be generated internally so the iv passed in
     * would be NULL. 
     */
    if (!EVP_EncryptInit_ex2(ctx, cipher_type, gcm_key, gcm_iv, params))
        goto err;

#if 0
    /* Zero or more calls to specify any AAD */
    if (!EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad)))
        goto err;
#endif

	while(1) {
		const size_t BUFFER_SIZE = 8 * 1024;
		unsigned char inbuf[BUFFER_SIZE];
		unsigned char outbuf[BUFFER_SIZE + cipher_block_size];
		int bytes_read;
		int outlen;
		int bytes_written;

		bytes_read = read(input_fd, inbuf, sizeof inbuf);
		if(!bytes_read)
			break;
		else if(bytes_read < 0) {
			fprintf(stderr, "problem with read: %s\n", strerror(errno));
			goto err;
		}

		total_bytes_read += bytes_read;
		if(optional_bytes && total_bytes_read > optional_bytes)
			break;

		/* Encrypt plaintext */
		if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, bytes_read))
       			 goto err;

		/* Output encrypted block */
		bytes_written = write(output_fd, outbuf, outlen);
		if(bytes_written < 0) {
			fprintf(stderr, "problem with write: %s\n", strerror(errno));
			goto err;
		} else if(bytes_written != outlen) {
			fprintf(stderr, "problem with write: wrote %d bytes, wanted %d\n", bytes_written,
								outlen);
			goto err;
		}
	}
		

    /* Finalise: note get no output for GCM */
    if (!EVP_EncryptFinal_ex(ctx, temp_buf, &tmplen))
        goto err;

    assert(tmplen == 0);

    /* Get tag */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  outtag, 16);

    if (!EVP_CIPHER_CTX_get_params(ctx, params))
        goto err;

    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, outtag, 16);

    write(output_fd, outtag, sizeof outtag);

    ret = true;
err:
    if (ret == false)
        ERR_print_errors_fp(stderr);

//    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}


int aes_gcm_decrypt(int input_fd, int output_fd, unsigned char *aad, int aad_len,
				unsigned char *gcm_key, // 32 chars
				unsigned char *gcm_iv, size_t gcm_ivlen)
{
    bool ret = false;
    EVP_CIPHER_CTX *ctx;
    OSSL_PARAM params[2] = {
        OSSL_PARAM_END, OSSL_PARAM_END
    };
    unsigned char gcm_tag[16];
    size_t cipher_block_size = EVP_CIPHER_block_size(cipher_type);
    size_t total_bytes_read = 0;
    size_t total_bytes_desired;
    int  count;
    off_t start_of_file;
    unsigned char buffer[1024];
    int buflen;


    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;


#if 0
    /* Fetch the cipher implementation */
    if ((cipher = EVP_CIPHER_fetch(libctx, "AES-256-GCM", propq)) == NULL)
        goto err;
#endif

	/* Set IV length if default 96 bits is not appropriate */
	params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
					    &gcm_ivlen);

	/*
	* Initialise an encrypt operation with the cipher/mode, key, IV and
	* IV length parameter.
	*/
	if (!EVP_DecryptInit_ex2(ctx, cipher_type, gcm_key, gcm_iv, params))
		goto err;

	total_bytes_desired = lseek(input_fd, -16, SEEK_END);

	if(total_bytes_desired < 0) {
	    fprintf(stderr, "Cannot lseek tag, %s\n", strerror(errno));
	    goto err;
	}

	count = read(input_fd, gcm_tag, sizeof gcm_tag);
	if(count < 0) {
		fprintf(stderr, "read tag failed: %s\n", strerror(errno));
		goto err;
	}

   	/* go back to beginning of file */
    	start_of_file = lseek(input_fd, 0, SEEK_SET);
   	if(start_of_file < 0) {
		fprintf(stderr, "cannot rewind file: %s\n", strerror(errno));
		goto err;	
	}

#if 0
    /* Zero or more calls to specify any AAD */
    if (!EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad)))
        goto err;
#endif

	while(total_bytes_read < total_bytes_desired) {
		const int BUF_SIZE = 8 * 1024;
		unsigned char inbuf[BUF_SIZE];
		unsigned char outbuf[BUF_SIZE + cipher_block_size];
		int outlen;
		int bytes_to_read;

		if(total_bytes_desired - total_bytes_read > sizeof inbuf)
			bytes_to_read = sizeof inbuf;
		else	bytes_to_read = total_bytes_desired - total_bytes_read;

		count  = read(input_fd, inbuf, bytes_to_read);
		assert(count == bytes_to_read);

		if(!EVP_DecryptUpdate(ctx, outbuf, &outlen,  inbuf, count)) {
			fprintf(stderr, "EVP_DecryptUpdate failed\n");
			goto err;
		}

		total_bytes_read += count;
		count = write(output_fd, outbuf, outlen);
		assert(count == outlen);
	}


	/* Set expected tag value. */
	params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  (void*)gcm_tag, sizeof(gcm_tag));


        if (!EVP_CIPHER_CTX_set_params(ctx, params))
		goto err;

	/* Finalise: note get no output for GCM */
	int rv = EVP_DecryptFinal_ex(ctx, buffer, &buflen);
    /*
     * Print out return value. If this is not successful authentication
     * failed and plaintext is not trustworthy.
     */
    printf("Tag Verify %s, buflen = %d\n", rv > 0 ? "Successful!" : "Failed!", buflen);

    ret = true;
err:
    if (false == ret)
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_CTX_free(ctx);

    return ret;
}


			
#if 0
static int gcm_encrypt(int input_fd, int output_fd,
		int bytes,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) 
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Setting IV len to 7. Not strictly necessary as this is the default
     * but shown here for the purposes of this example.
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
        handleErrors();

    /* Set tag length */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, NULL);

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /* Provide the total plaintext length */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len))
        handleErrors();

    /* Provide any AAD data. This can be called zero or one times as required */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can only be called once for this.
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in CCM mode.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 14, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
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


static bool construct_iv(char *iv, int size)
{
#ifdef ZERO_IV
	memset(iv, 0, size);
#else
	if(getrandom(iv, size, 0) != size)
		return false;
#endif
	return true;
}
	
bool do_encrypt(const char *input, const char *output, size_t bytes, const uint8_t key[AES_256_BLOCK_SIZE])
{
	int input_fd;
	int output_fd;
	int retval;
	bool result = false;	// default failure
//	char iv[AES_BLOCK_SIZE];
	char iv[12];


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

	result = construct_iv(iv, sizeof iv);	
	if(result == false) {
		fprintf(stderr, "cannot get random iv: %s\n", strerror(errno));
		goto failure;
	}

#ifdef SAVE_IV
	write(output_fd, iv, sizeof iv);
#endif
	switch(enum_cipher) {
		case  AES_256_GCM:
			result = aes_gcm_encrypt(input_fd,  output_fd, bytes, NULL, 0, key, iv, sizeof iv);
			break;
		case  AES_256_CBC:
//			result = do_cbc(true, input_fd, output_fd, bytes, key, iv);
//			break;
		default:
			fprintf(stderr, "unknown cipher\n");
			abort();
	}

failure:
	close(input_fd);
	close(output_fd);
	return result;

}


bool do_decrypt(const char *input, const char *output, const uint8_t key[AES_256_BLOCK_SIZE])
{

	int input_fd;
	int output_fd;
	int retval;
	bool result = false;	// default failure
//	char iv[AES_BLOCK_SIZE];
	unsigned char iv[12];

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


#ifdef SAVE_IV
	retval = read(input_fd, iv,  sizeof iv);
	if(retval != sizeof iv) {
		fprintf(stderr, "can't read  saved iv\n");
		exit(1);
	}
#else

#ifndef ZERO_IV
	printf("haven't defined ZERO_IV\n");
	exit(1);
#endif

	memset(iv, 0, sizeof iv);
#endif


	switch(enum_cipher) {
		case  AES_256_GCM:
			result = aes_gcm_decrypt(input_fd,  output_fd, NULL, 0, key, iv, sizeof iv);
			break;
		case  AES_256_CBC:
//			result = do_cbc(true, input_fd, output_fd, bytes, key, iv);
//			break;
		default:
			fprintf(stderr, "unknown cipher\n");
			abort();
	}

failure:
	close(input_fd);
	close(output_fd);
	return result;

}	

void select_cipher_type(enum cipher_type type)
{
	switch(type) {
		case AES_256_GCM:
			cipher_type = EVP_aes_256_gcm();
			authenticated = true;
			break;
		case AES_256_CBC:
			cipher_type = EVP_aes_256_cbc();
			authenticated = false;
			break;
		case AES_256_CTR:
			cipher_type = EVP_aes_256_ctr();
			authenticated = false;
			break;
		default:
			printf("illegal cipher type\n");
			abort();
	}
	
	enum_cipher = type;

}

static __attribute__((constructor)) void init(void)
{
	select_cipher_type(AES_256_GCM);
}
