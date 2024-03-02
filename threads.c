#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
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

static bool  input_dev_zero = false;
static bool output_dev_null = false;

static  pthread_mutex_t able_to_condition = PTHREAD_MUTEX_INITIALIZER;
static  pthread_cond_t cv = PTHREAD_COND_INITIALIZER;

struct thread_info {
	int input;	// fd
	int output;	// fd
	size_t bytes;	
	struct timeval time_started;
	pthread_mutex_t work_available;   // unlocked to start work , 
	volatile bool done;		// work finished, unlock work_avilable to start new work cycle
	bool terminated;		// thread is terminted
	pthread_t thread_info;
};



static struct thread_info *each_thread;
static int num_threads = 1;

#define AES_256_KEY_SIZE    32
#define AES_BLOCK_SIZE	    16
static enum { ENCRYPT, DECRYPT, COPY } type_of_op = COPY;
static const uint8_t aes_key[AES_256_KEY_SIZE] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
						   11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
						   21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
						   31, 32
						};
static const uint8_t iv[AES_BLOCK_SIZE] = { 0 };


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

static double timeval_to_seconds(struct timeval t)
{
	double seconds;

	seconds = t.tv_sec;
	seconds += t.tv_usec / (1000.0 * 1000.0);

	return seconds;
}

static void *copy_file(void *args)
{
	struct thread_info *p = (struct thread_info *) args;

	while(1) {
		int bytes_copied = 0;

		pthread_mutex_lock(&p->work_available);
		
		while(bytes_copied < p->bytes) {
			int bytes_read;
			char buffer[8192];

			bytes_read = read(p->input,  buffer, sizeof buffer);
			if(bytes_read > 0) {
				safe_write(p->output, buffer, bytes_read);
			} else if(0 == bytes_read) {
				printf("EOF: bytes_copied = %d\n", bytes_copied);
				break;
			}
			bytes_copied += bytes_read;
		}	
		p->done = true;
		pthread_cond_broadcast(&cv);
	}
	return NULL;
}

// encrypt/decrypt threads arguments 
struct  aes_info {
	bool encrypt;	// true to encrypt, false to decrept;
	const uint8_t key[AES_256_KEY_SIZE];
	const uint8_t iv[AES_BLOCK_SIZE];
	int input_fd;
	int output_fd;
	size_t input_size;
};

static void *encrypt_decrypt(void *args)
{
	struct aes_info *aes_info = (struct aes_info *) args;

	return NULL;
}



static void create_thread_structure(void)
{
	each_thread = calloc(sizeof(struct thread_info), num_threads);
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
	exit(1);

}


static DIR *dir;

static void prime_opendir(void)
{
	dir = opendir(directory);
	if(!dir) {
		fprintf(stderr, "cannot opendir(%s):%s\n", directory, strerror(errno));
		exit(1);	
	}
}

/* open input and output, and return the size.
 * If  we did, return TRUE.
 * If not, return false;
 */
static bool next_file(int *input, int *output, size_t *size)
{
	if(true == input_dev_zero) {
		static int num_times = 100;
		const size_t GIG = 1000 * 1000 * 1000;

		if(!num_times)
			return false;


		*input = open("/dev/zero", O_RDONLY);
		assert(*input >= 0);
		*output = open("/dev/null", O_WRONLY);
		assert(*output >= 0);
		*size = GIG;
		num_times--;
	} else {
		struct dirent *dirent;
		char dest[256 + 5];	// slightly bigger
		struct stat stat;
		int result;

		dirent = readdir(dir);
		if(!dirent) {
			fprintf(stderr, "EOF on readdir\n");
			return false;
		}

		*input = open(dirent->d_name, O_RDONLY);
		if(*input < 0)  {
			fprintf(stderr, "cannot open %s: %s\n", dirent->d_name, strerror(errno));
			exit(1);
		}
		if(output_dev_null == true)
			strcpy(dest, "/dev/null");
		else switch(type_of_op) {
			case COPY:
				snprintf(dest, sizeof dest, "%s.copy", dirent->d_name);
				break;
			case ENCRYPT:
				snprintf(dest, sizeof dest, "%s.enc", dirent->d_name);
				break;
			case DECRYPT:
				snprintf(dest, sizeof dest, "%s.dec", dirent->d_name);
				break;
			default:
				fprintf(stderr, "problem\n");
				abort();
		}
				
		*output = open(dest, O_WRONLY | O_CREAT, 0666);
		if(*output < 0) {
			fprintf(stderr, "cannot create %s: %s\n", dest, strerror(errno));
			exit(1);
		}

		result = fstat(*input, &stat);
		if(result < 0) {
			fprintf(stderr, "cannot stat %s: %s\n", dirent->d_name, strerror(errno));
			exit(1);
		}
		*size = stat.st_size;
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
		next_file(&pthread->input, &pthread->output, &pthread->bytes);
#if 0
		pthread->input = open("/dev/zero", O_RDONLY);
		assert(pthread->input >= 0);
		pthread->output = open("/dev/null", O_WRONLY);
		assert(pthread->output >= 0);
#endif
		pthread->done = false;
		bytes_transferred +=  pthread->bytes;
		result = pthread_create(&pthread->thread_info, NULL, copy_file, pthread);
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

				close(pthread->input);
				close(pthread->output);


				another_file = next_file(&pthread->input, &pthread->output, &pthread->bytes);

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

	timersub(&end_time, &start_time, &delta_time);
	microseconds = delta_time.tv_sec * 1000 * 1000;
	microseconds += delta_time.tv_usec;
//	printf("bytes = %lld, seconds = %.3f\n", bytes_transferred, microseconds / (1000 * 1000));
	gigabytes = bytes_transferred / (1000 * 1000.0 * 1000.0);
	seconds = microseconds / (1000.0 * 1000.0);
	printf("gig/sec = %.3f\n", gigabytes / seconds);

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

		c = getopt(argc, argv, "t:zd:nhDE");
		if(-1 == c) 
			break;
		switch(c) {
			case 't':
				num_threads = strtol(optarg, NULL, 10);
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
	do_work();
}



