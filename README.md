# Faster encryption with libcyrpto

This is an implementation of AES-256-GCM    libcrypto on modern processors uses the AES-NI instructions, 
which speed up encryption/decryption by 6-10x.

To APIs are used which need to be incorporated in dart via a FFI.

## File Format

The file format is simple:

  * Magic number (HYPN) to identify encrypted files easily
  * SHA256 (32 bytes) of the AES key -- to confirm the right key is being used
  * 12 byte random IV
  * body of encrypted file
  * 16 byte gcm tag (to be read when encrypting)

## Encryption

	#include "encrypt.h"
	
	enum encrypt_result {
	        ENCRYPT_SUCCESSFUL,
	        ENCRYPT_NO_CTX,
	        ENCRYPT_GET_PARAMS_FAILED,
	        ENCRYPT_INIT_FAILED,
	        ENCRYPT_WRITE_FAILED,
	        ENCRYPT_READ_PROBLEM,
	        ENCRYPT_UPDATE_FAILED,
	        ENCRYPT_CANNOT_OPEN_INPUT,
	        ENCRYPT_CANNOT_OPEN_OUTPUT,
	        ENCRYPT_CANNOT_COMPUTE_SHA256,
	        ENCRYPT_FINAL_FAILED,
	        ENCRYPT_FAILURE  
	};
	
	
	 enum encrypt_result do_encrypt(const char *input_file, const char *output_file, size_t optional_size, const uint8_t key_256[32]);
	
The following parameters are used:  
  
  * input file  -- must be present
  * output file -- must be able to write to it (will be created if not present)
  * optional_size -- useful when doing benchmarking from /dev/zero to /dev/null.    Specifies "how much data" to encrypt.    If 0, encrypt until EOF.
  * key_256 -- the 32 byte key for AES 256

It returns TRUE is the encryption works, and FALSE if there is a problem.

If there is a problem, there may be output left in output_file

## Decryption

	#include "encrypt.h"
	
	enum decrypt_result {
	        DECRYPT_SUCCESSFUL,
	        DECRYPT_NO_CTX,
	        DECRYPT_INIT_FAILED,
	        DECRYPT_LSEEK_FAILED,
	        DECRYPT_READ_TAG_FAILED,
	        DECRYPT_UPDATE_FAILED,
	        DECRYPT_WRITE_FAILED,   
	        DECRYPT_READ_FAILED,
	        DECRYPT_MAGIC_FAILED,
	        DECRYPT_AES_KEY_FAILED,
	        DECRYPT_SET_PARAMS_FAILED,
	        DECRYPT_TAG_COMPARE_FAILED,
	        DECRYPT_OPEN_INPUT_FAILED,
	        DECRYPT_OPEN_OUTPUT_FAILED,
	        DECRYPT_CANNOT_READ_MAGIC,
	        DECRYPT_BAD_MAGIC,
	        DECRYPT_CANNOT_READ_IV,
	        DECRYPT_CANNOT_READ_SHA,
	        DECRYPT_SHA_COMPARE_FAILED
	};
	
	
	enum decrypt_result  do_decrypt(const char *input_file, const char *output_file, const uint8_t key_256[32]);
	
The following parameters are needed:  

  * input_file - are readable input file which needs to exist (it can be NULL)
  * output_file -- the name of a file (which may be created) which is writable
  * key_256 -- a 32 byte AES key

It returns TRUE if the decryption works without problem (checking the MAC in the input file against the encryption),   
FALSE if there is a problem.

If there is a problem, there may be output in the output file.


## Encrypt/decrypt with threads

		#include "openssl_threads.h"
		
		struct threaded_entry {
			const char *input_file;	// name of input file
			const char *output_file;    // name of output file
			bool completed;
			int errno_value;	/* useful when status shows a system called
							 * failed 
							 */
			union {
				enum decrypt_result decrypt_status;
				enum encrypt_result encrypt_status;
			};
	
	       };
	      
          // OP_COPY is for benchmarking purposes
          enum openssl_operation {  OP_COPY, OP_ENCRYPT, OP_DECRYPT };

	      int openssl_with_threads(struct thread_entry *array, 
	       			int num_entries, 
	       			int num_threads,
	       			unsigned char aes_key[32],	/* for AES 256 */
                    enum openssl_operation op_type,
	       			bool  (*callback)(struct thread_entry *entry, enum openssl_operation op_type,
                                    size_t size);
	       


The callback is optional.   If its NULL, no callback is used.
If there is a callback, true means "keep going".  False means "stop when all threads complete.    The size can be used to compute "number of files" and "size"

num_entries is the size of array.

num_threads is the number of threads to use.

The key is AES 256 key to use.

openssl_operation defines the operation type (ENCRYPT, DECRYPT or COPY)

It returns the number of files processed (working cases is num_entries is the return value.


## Making the software

The makefile is structured with:

  * XCFLAGS -- to pass arbitrary commands to the C compile
  * DEFINES -- software currently uses  
        * -DSAVE_IV -- save IV in the output file during encryption (could be random)  
        * -DZERO_IV -- IV is a byte stream of zeros -- useful for testing and not saving the IV  
        * -DBUFFER_SIZE=nnn -- set the BUFFER_SIZE instead of 8k 


It needs to be used on a relatively recent version of openssl (it appears the API was extended to help with AEAD encryption)

I know this works (from ubuntu 22.04):  


openssl version
OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

and this doesn't (from ubuntu 20.04)
openssl version
OpenSSL 1.1.1f  31 Mar 2020



