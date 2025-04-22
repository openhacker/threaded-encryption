#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "openssl_threads.h"



static uint8_t aes_key[AES_256_KEY_SIZE] = { 0 } ;


static long long unsigned bytes_processed;


static struct thread_entry *create_zero_entries(int num)
{
	struct thread_entry *entries;
	struct thread_entry *pentry;

	entries = calloc(sizeof *entries, num);

	for(pentry = entries; pentry < entries + num; pentry++) {
		pentry->input_file = strdup("/dev/zero"); 
		pentry->output_file = strdup("/dev/null");
	}

	return entries;
}
		

static bool callback(struct thread_entry *entry, enum openssl_operation op_type, size_t size )
{
	static int count = 0;
	static bool track = false;

	count++;
	if(!(count % 10) && track)
		printf("processed %d\n", count);

//	printf("%d: processed %ld bytes\n", ++total_processed, size);
	bytes_processed += size;
	return true;
}


static void usage(const char *string)
{
	printf("%s\n\n", string);
	printf("\t-t\tnum threads\n");
	printf("\t-c\nuse copy rather than encrypt (raw io)\n");
	printf("\t -i iterations\n");
	

	exit(1);
}

int main(int argc, char *argv[])
{

	struct thread_entry *entries;
	int num = 100;
	int num_threads = 1;
	enum openssl_operation op = OP_ENCRYPT;;

	while(1) {
		int c;

		c = getopt(argc, argv, "t:ci:");
		if(-1 == c)
			break;
		switch(c) {
			case 't':
				num_threads = atoi(optarg);
				break;
			case 'c':
				op =  OP_COPY;
				break;
			case 'i':
				num = atoi(optarg);
				break;
			default:
				usage("illegal option");
				break;
		}

	}



	printf("running %d iterations\n", num);		

	entries = create_zero_entries(num);

	setenv("DEV_ZERO", "1", 1);

	openssl_with_threads(entries, num, num_threads, aes_key,  op, callback);

	return 0;

}

