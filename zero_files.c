#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "openssl_threads.h"



static uint8_t aes_key[AES_256_KEY_SIZE] = { 0 } ;


static int total_processed = 0;
static long long unsigned bytes_processed;

static int one_k = 1024;

static struct threaded_entry *create_zero_entries(int num)
{
	struct thread_entry *entries;
	struct thread_entry *pentry;

	entries = calloc(sizeof *entries, num);

	for(pentry = entries; pentry < entries + num; pentry++) {
		strcpy(pentry->input_file, "/dev/zero");
		strcpy(pentry->output_file, "/dev/null");
	}

	return entries;
}
		

static void callback(struct thread_entry *entry, enum openssl_operation op_type, size_t size )
{
	static int count = 0;

	count++;
	if(!(count % 10))
		printf("processed %d\n", count);
//	printf("%d: processed %ld bytes\n", ++total_processed, size);
	bytes_processed += size;
}


main(int argc, char *argv[])
{

	struct threaded_entry *entries;
	int num = 100;
	int num_threads = 1;
	struct timeval start_time;
	struct rusage start_rusage;
	struct timeval end_time;
	struct rusage end_rusage;
	double microseconds;
	double seconds;
	double gigabytes;
	struct timeval delta_time;


	if(argc > 2)
		exit(1);

	if(argc == 2)
		num_threads = atoi(argv[1]);
		
	num = 100;

	entries = create_zero_entries(num);
	printf("threads =  %d\n", num_threads);
	gettimeofday(&start_time, NULL);
	getrusage(RUSAGE_SELF, &start_rusage);

	setenv("DEV_ZERO", "1", 1);

	openssl_with_threads(entries, num, num_threads, aes_key,  OP_ENCRYPT, callback);

	gettimeofday(&end_time, NULL);
	getrusage(RUSAGE_SELF, &end_rusage);
	timersub(&end_time, &start_time, &delta_time);
	microseconds = delta_time.tv_sec * 1000 * 1000;
	microseconds += delta_time.tv_usec;
	gigabytes= bytes_processed / ( 1000.0 * 1000.0 * 1000.0);
	seconds = microseconds/ (1000.0 * 1000.0);
	printf("gig/sec = %.3f\n", gigabytes/seconds);
}

