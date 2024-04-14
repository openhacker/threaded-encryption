#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl_threads.h"


static struct threaded_entry *create_zero_entries(int num)
{
	struct thread_entry *entries;
	struct thread_entry *pentry;

	entries = calloc(sizeof *entries, num);

	for(pentry = entries; pentry < entries + num; pentry++) {
		strcpy(pentry->input_file, "/dev/zero");
		strcpy(pentry->output_file, "/dev/null");
		pentry->encrypt = true;
	}

	return entries;
}
		


main(int argc, char *argv)
{

	struct threaded_entry *entries;
	int num;
	int num_threads = 1;
	const char key[32] = { 0 };

	if(argc > 2)
		exit(1);

	if(argc == 2)
		num_threads = atoi(argv[1]);
		
	num = 100;

	entries = create_zero_entries(num);
	printf("threads =  %d\n", num_threads);
	openssl_with_threads(entries, num, num_threads, key, NULL);

}

