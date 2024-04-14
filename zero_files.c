#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl_threads.h"



static uint8_t aes_key[AES_256_KEY_SIZE] = { 0 } ;


static int one_k = 1024;

static struct threaded_entry *create_zero_entries(int num)
{
	struct thread_entry *entries;
	struct thread_entry *pentry;

	entries = calloc(sizeof *entries, num);

	for(pentry = entries; pentry < entries + num; pentry++) {
		strcpy(pentry->input_file, "/dev/zero");
		strcpy(pentry->output_file, "/dev/null");
		memcpy(pentry->aes_key, aes_key, sizeof aes_key);
		pentry->encrypt = true;
		pentry->size = one_k * one_k * one_k;
	}

	return entries;
}
		

static void callback(struct thread_entry *entry)
{
	static int i = 0;

	printf("%d: processed %ld bytes\n", i++, entry->size);
}


main(int argc, char *argv[])
{

	struct threaded_entry *entries;
	int num = 100;
	int num_threads = 1;

	if(argc > 2)
		exit(1);

	if(argc == 2)
		num_threads = atoi(argv[1]);
		
	num = 100;

	entries = create_zero_entries(num);
	printf("threads =  %d\n", num_threads);
	openssl_with_threads(entries, num, num_threads, callback);

}

