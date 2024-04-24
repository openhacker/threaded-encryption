#ifndef _OPENSSL_THREADS_H
#define _OPENSSL_THREADS_H

#include <limits.h>
#include <stdint.h>
#include "encrypt.h"


#define AES_256_KEY_SIZE    32

struct thread_entry {
	char *input_file;	// name of input file
	char *output_file;    // name of output file
	bool completed;
	int errno_value;	/* useful when status shows a system called
					 * failed 
					 */
	union {
		enum decrypt_result decrypt_status;
		enum encrypt_result encrypt_status;
	};

};

enum openssl_operation { OP_COPY, OP_ENCRYPT, OP_DECRYPT };

int openssl_with_threads(struct thread_entry *array, 
		int num_entries, 
		int num_threads,
		uint8_t AES_key[AES_256_KEY_SIZE],
		enum openssl_operation op_type,
		bool  (*callback)(struct thread_entry *entry, enum openssl_operation op_type, size_t size) );


void openssl_buffer_size(int size);

#endif

