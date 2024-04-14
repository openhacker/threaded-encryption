#ifndef _OPENSSL_THREADS_H
#define _OPENSSL_THREADS_H

#include <limits.h>
#include <stdint.h>
#include "encrypt.h"


#define AES_256_KEY_SIZE    32

struct thread_entry {
	char input_file[PATH_MAX];	// name of input file
	char output_file[PATH_MAX];    // name of output file
	uint8_t	aes_key[AES_256_KEY_SIZE];
	bool encrypt;   			// true if encrypt, false for decrypt
	bool do_delete;			// set to true to delete input or output
	bool completed;
	int errno_value;	/* useful when status shows a system called
					 * failed 
					 */
	size_t size;		/* only useful when benchmarking /dev/zero to /dev/null.
				 * otherwise 0
				 */
	union {
		enum decrypt_result decrypt_status;
		enum encrypt_result encrypt_status;
	};

};

int openssl_with_threads(struct thread_entry *array, 
		int num_entries, 
		int num_threads,
		bool  (*callback)(struct thread_entry *entry));

#endif

