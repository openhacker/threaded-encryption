#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>  // for ubuntu 16.04
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "encrypt.h"

static bool  input_dev_zero = false;
static bool output_dev_null = false;
enum operation_type { ENCRYPT, DECRYPT, COPY };
static int number_files = 0;	// files written

static enum operation_type type_of_op = COPY;

#define AES_256_KEY_SIZE    32
#define AES_BLOCK_SIZE	    16

static  pthread_mutex_t able_to_condition = PTHREAD_MUTEX_INITIALIZER;
static  pthread_cond_t cv = PTHREAD_COND_INITIALIZER;

struct thread_info {
	char input[PATH_MAX];	
	char output[PATH_MAX];	// fd
	size_t bytes;	
	struct timeval time_started;
	pthread_mutex_t work_available;   // unlocked to start work , 
	volatile bool done;		// work finished, unlock work_avilable to start new work cycle
	bool terminated;		// thread is terminted
	pthread_t thread_info;
	enum operation_type type_of_op;
	/* need the following for encrypt/decrypt */
	uint8_t key[AES_256_KEY_SIZE];
};



static struct thread_info *each_thread;
static int num_threads = 1;

#if 0
static const uint8_t aes_key[AES_256_KEY_SIZE] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
						   11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
						   21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
						   31, 32
						};

#else
static const uint8_t aes_key[AES_256_KEY_SIZE] =  {125, 223, 230, 12, 126, 250, 227, 251, 12, 184,
       						136, 43, 108, 184, 162, 191, 54, 101, 87, 212, 
						199, 180, 198, 100, 210, 118, 164, 7, 169, 232, 
								181, 172  };
#endif


static char *directory = NULL;

static void safe_write(int fd, char *buffer, int size)
{

	while(1) {
		int bytes_written;

		bytes_written = write(fd, buffer, size);
		if(bytes_written == size) 
			return;
		if(bytes_written < 0) {
			fprintf(stderr, "write failed: %s\n", strerror(errno));
		} else {
			fprintf(stderr, "partial write:  %lu wrote %d, wanted %d\n", pthread_self(),
									bytes_written, size);
			size -= bytes_written;
			buffer += bytes_written;
		}
	}

}

static bool disable_aesni = false;

static void disable_aesni_environment(void)
{
	int result;

	result = setenv("OPENSSL_ia32cap", "~0x200000200000000", 0);
	if(result < 0) {
		fprintf(stderr, "cannot set environment: %s\n", strerror(errno));
		exit(1);
	}
}

static double timeval_to_seconds(struct timeval t)
{
	double seconds;

	seconds = t.tv_sec;
	seconds += t.tv_usec / (1000.0 * 1000.0);

	return seconds;
}

static bool copy_file(const char *input, const char *output, size_t bytes)
{
	int input_fd;
	int output_fd;
	int bytes_copied = 0;


	input_fd = open(input, O_RDONLY);
	if(input_fd < 0) {
		fprintf(stderr, "cannot open input: %s: %s\n", input, strerror(errno));
		return false;
	}

	output_fd = open(output, O_WRONLY | O_CREAT, 0644);
	if(output_fd < 0) {
		fprintf(stderr, "cannot open output: %s: %s\n", output, strerror(errno));
		return false;
	}

	while(bytes_copied < bytes) {
		int bytes_read;
		char buffer[8192];

		bytes_read = read(input_fd,  buffer, sizeof buffer);
		if(bytes_read > 0) {
			safe_write(output_fd, buffer, bytes_read);
		} else if(0 == bytes_read) {
			printf("EOF: bytes_copied = %d\n", bytes_copied);
			break;
		}
		bytes_copied += bytes_read;
	}
	return true;
}


static void *encrypt_decrypt_copy(void *args)
{
	struct thread_info *aes_info = (struct thread_info *) args;

	while(1) {
		bool result; 

		pthread_mutex_lock(&aes_info->work_available);
		
		switch(aes_info->type_of_op) {
			case ENCRYPT:
				result = do_encrypt(aes_info->input, aes_info->output, aes_info->bytes, aes_info->key);
				break;
			case DECRYPT:
				result = do_decrypt(aes_info->input, aes_info->output, aes_info->key);
				break;
			case COPY:
				result = copy_file(aes_info->input, aes_info->output, aes_info->bytes);
				break;
			default:
				abort();
		}

		if(false == result)  {
			fprintf(stderr, "problem\n");
		}
		aes_info->done = true;
		pthread_cond_broadcast(&cv);
	}

	return NULL;
}



static void create_thread_structure(void)
{
	struct thread_info  *pthread;
	each_thread = calloc(sizeof(struct thread_info), num_threads);
	for(pthread = each_thread; pthread < each_thread + num_threads; pthread++) {
		pthread->type_of_op = type_of_op;
		memcpy(pthread->key, aes_key, sizeof aes_key);
	}
}


static void usage(const char *message)
{
	if(message) {
		fprintf(stderr, "%s\n", message);
	}

	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\tt\tnum threads (default 1)\n");
	fprintf(stderr, "\tz\trun /dev/zero to /dev/null\n");
	fprintf(stderr, "\td\tdirectory\trun from files in a  directory\n");
	fprintf(stderr, "\tn\trun files to /dev/null\n");
	fprintf(stderr, "\tD\tdo decryption (default COPY)\n");
	fprintf(stderr, "\tE\tdo encryption (default COPY)\n");
	fprintf(stderr, "\to\tsend output to /dev/null (for directory)\n");
	fprintf(stderr, "\ta\tselect algorithm -- default aes_256_cbc, use to change to aes_256_gcm\n");
	fprintf(stderr, "\tA\tdisable AES engine\n");
	exit(1);

}


static char **filenames = NULL;
static int num_filenames;

static void prime_opendir(void)
{
	DIR *dir;
	struct dirent *dirent;

	dir = opendir(directory);
	if(!dir) {
		fprintf(stderr, "cannot opendir(%s):%s\n", directory, strerror(errno));
		exit(1);	
	}
	while( (dirent = readdir(dir)) ) {
		if(!strcmp(dirent->d_name, ".") || !strcmp(dirent->d_name, ".."))
				continue;
		num_filenames++;
#if 0
		filenames = reallocarray(filenames, num_filenames, sizeof(char *));
#else
		filenames = realloc(filenames, num_filenames * sizeof(char *));
#endif
		assert(filenames);
		filenames[num_filenames - 1] = strdup(dirent->d_name);
	}
	closedir(dir);

#if 0
	for(int i = 0; i < num_filenames; i++) 
		printf("%d = %s\n", i, filenames[i]);
#endif

}

/* open input and output, and return the size.
 * If  we did, return TRUE.
 * If not, return false;
 */
static bool next_file(char *input,  char *output, size_t *size)
{
	if(true == input_dev_zero) {
		static int num_times = 100;
		const size_t GIG = 1000 * 1000 * 1000;

		if(!num_times)
			return false;


		strcpy(input, "/dev/zero");
		strcpy(output, "/dev/null");
		number_files++;
		*size = GIG;
		num_times--;
	} else {
		struct stat statbuf;
		int result;
		char *name;
		char dest[256];


		if(number_files >= num_filenames)
			return false;
		name = filenames[number_files];

		strcpy(input, name);

		result = stat(input, &statbuf);
		if(result < 0) {
			fprintf(stderr, "cannot stat %s: %s\n", input, strerror(errno));
			return false;
		}

		*size = statbuf.st_size;

		number_files++;
		if(output_dev_null == true)
			strcpy(output, "/dev/null");
		else switch(type_of_op) {
			case COPY:
				snprintf(dest, sizeof dest, "%s.copy", name);
				break;
			case ENCRYPT:
				snprintf(dest, sizeof dest, "%s.enc", name);
				break;
			case DECRYPT:
				snprintf(dest, sizeof dest, "%s.dec", name);
				break;
			default:
				fprintf(stderr, "problem\n");
				abort();
		}
				
		strcpy(output, dest);

		if(result < 0) {
			fprintf(stderr, "cannot stat %s: %s\n", name, strerror(errno));
			exit(1);
		}
		*size = statbuf.st_size;
	}
	return true;
}

static void run_threads(void)
{
	int work_left = 100;
	struct thread_info *pthread;
	long long int bytes_transferred = 0;
	struct timeval start_time;
	struct rusage start_rusage;

	gettimeofday(&start_time, NULL);
	getrusage(RUSAGE_SELF,  &start_rusage);

	if(directory)
		prime_opendir();


	for(pthread = each_thread; pthread  < each_thread + num_threads; pthread++) {
		int result;

		result = pthread_mutex_init(&pthread->work_available, NULL);

		result = pthread_mutex_lock(&pthread->work_available);
		assert(result == 0);
		next_file(pthread->input, pthread->output, &pthread->bytes);
		
		pthread->done = false;
		bytes_transferred +=  pthread->bytes;
			
		result = pthread_create(&pthread->thread_info, NULL, encrypt_decrypt_copy, pthread);
		assert(result == 0);
	}

	pthread_mutex_lock(&able_to_condition);
	work_left -= num_threads;	

	for(pthread = each_thread; pthread < each_thread + num_threads; pthread++) {
		pthread_mutex_unlock(&pthread->work_available);
	}

	while(1) {
		pthread_cond_wait(&cv, &able_to_condition);

		for(pthread = each_thread; pthread < each_thread + num_threads; pthread++) {
			if(pthread->done == true) {
				bool another_file;



				another_file = next_file(pthread->input, pthread->output, &pthread->bytes);

				if(false == another_file) {
					pthread->terminated = true;
					pthread->done = false;
					pthread_cancel(pthread->thread_info);
				} else {
					pthread->done = false;
					bytes_transferred += pthread->bytes;
					pthread_mutex_unlock(&pthread->work_available);
				}
			}
		}
		
		bool not_terminated = false;

		/* if all threads terminated, exit */
		for(pthread = each_thread; pthread < each_thread + num_threads; pthread++) {
			if(pthread->terminated == false) {
				not_terminated = true;
				break;
			} 
		}

		if(not_terminated == false) {
			break;
		}
	}

	struct timeval end_time;
	struct timeval delta_time;
	double microseconds;
	double seconds;
	struct rusage end_rusage;
	struct timeval delta_usertime;
	struct timeval delta_systime;
	double gigabytes;

	gettimeofday(&end_time, NULL);
	getrusage(RUSAGE_SELF, &end_rusage);


	fprintf(stderr, "created %d files\n", number_files);
#if 0
	fprintf(stderr, "%s\tthreads = %d\t", algorithm == false ? "aes-256-cbc" :
								"aes-256-gcm", num_threads);
#endif
	timersub(&end_time, &start_time, &delta_time);
	microseconds = delta_time.tv_sec * 1000 * 1000;
	microseconds += delta_time.tv_usec;

	gigabytes = bytes_transferred / (1000 * 1000.0 * 1000.0);
	seconds = microseconds / (1000.0 * 1000.0);
	printf("gig/sec = %.3f\t", gigabytes / seconds);

	timersub(&end_rusage.ru_utime, &start_rusage.ru_utime, &delta_usertime);
	timersub(&end_rusage.ru_stime, &start_rusage.ru_stime, &delta_systime);

	printf("wall time =  %.3f user time = %.3f, systime = %.3f\n",
			timeval_to_seconds(delta_time), timeval_to_seconds(delta_usertime), timeval_to_seconds(delta_systime));
	
}
				

static void do_work(void)
{
	if(directory)
		chdir(directory);
	run_threads();
}

int main(int argc, char *argv[])
{

	while(1) {
		int c;

		c = getopt(argc, argv, "At:zod:nhDE");
		if(-1 == c) 
			break; 
		switch(c) {
#if 0
			case 'a':
				algorithm = true;
				break;
#endif
			case 'A':
				disable_aesni = true;
				break;
			case 't':
				num_threads = strtol(optarg, NULL, 10);
				break;
			case 'o':
				output_dev_null = true;
				break;
			case 'z':
				input_dev_zero = true;
				break;
			case 'd':
				directory = strdup(optarg);
				break;
			case 'n':
				output_dev_null = true;
				break;
			case 'h':
				usage(NULL);
				break;
			case 'D':
				type_of_op = DECRYPT;
				break;
			case 'E':
				type_of_op = ENCRYPT;
				break;	
			default:	
				usage("Unknown option");
				break;
		}	

	}
	fprintf(stderr, "threads = %d, /dev/zero = %d\n", num_threads, input_dev_zero);

	create_thread_structure();
	if(true == disable_aesni)
		disable_aesni_environment();

	do_work();
}



