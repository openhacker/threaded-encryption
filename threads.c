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

static bool  run_dev_zero = false;

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
			size -= bytes_written;
			buffer += bytes_written;
		}
	}

}

static void *copy_file(void *args)
{
	struct thread_info *p = (struct thread_info *) args;
	int times = 0;

	while(1) {
		int bytes_copied = 0;

		printf("thread %d: %d\n", (int) pthread_self(), times++);

		pthread_mutex_lock(&p->work_available);
		
		while(bytes_copied < p->bytes) {
			int bytes_read;
			int bytes_written;
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
		fprintf(stderr, "%d ended work\n", (int) pthread_self());
	}
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
	
	exit(1);

}



/* open input and output, and return the size.
 * If  we did, return TRUE.
 * If not, return false;
 */
static bool next_file(int *input, int *output, size_t *size)
{
	if(true == run_dev_zero) {
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
		return true;
	} else {
		abort();
	}
}

static void run_threads(void)
{
	int i;
	int work_left = 100;
	struct thread_info *pthread;
	long long int bytes_transferred = 0;
	struct timeval start_time;
	struct rusage start_usage;


	gettimeofday(&start_time, NULL);
	getrusage(RUSAGE_SELF,  &start_usage);


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
	struct rusage end_rusage;


	gettimeofday(&end_time, NULL);
	getrusage(RUSAGE_SELF, &end_rusage);

	timersub(&end_time, &start_time, &delta_time);
	microseconds = delta_time.tv_sec * 1000 * 1000;
	microseconds += delta_time.tv_usec;
	printf("bytes = %lld, seconds = %.3f\n", bytes_transferred, microseconds / (1000 * 1000));
	
}
				

static void do_work(void)
{
	run_threads();
}

main(int argc, char *argv[])
{

	while(1) {
		int c;

		c = getopt(argc, argv, "t:z");
		if(-1 == c) 
			break;
		switch(c) {
			case 't':
				num_threads = strtol(optarg, NULL, 10);
				break;
			case 'z':
				run_dev_zero = true;
				break;
			default:	
				usage("Unknown option");
				break;
		}	

	}
	fprintf(stderr, "threads = %d, /dev/zero = %d\n", num_threads, run_dev_zero);

	create_thread_structure();
	do_work();
		
}


