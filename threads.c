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

static void threads_zero_to_null(void)
{
	int i;
	const size_t size = 1000 * 1000 * 1000;	
	int work_left = 100;
	struct thread_info *pthread;

	for(pthread = each_thread; pthread  < each_thread + num_threads; pthread++) {
		int result;

		result = pthread_mutex_init(&pthread->work_available, NULL);

		result = pthread_mutex_lock(&pthread->work_available);
		assert(result == 0);
		pthread->input = open("/dev/zero", O_RDONLY);
		assert(pthread->input >= 0);
		pthread->output = open("/dev/null", O_WRONLY);
		assert(pthread->output >= 0);
		pthread->done = false;
		pthread->bytes = size;
		result = pthread_create(&pthread->thread_info, NULL, copy_file, pthread);
		assert(result == 0);
	}

	pthread_mutex_lock(&able_to_condition);
	work_left -= num_threads;	

	for(pthread = each_thread; pthread < each_thread + num_threads; pthread++) {
		pthread_mutex_unlock(&pthread->work_available);
	}

	while(1) {
		printf("number of workers left = %d\n", work_left);

		pthread_cond_wait(&cv, &able_to_condition);

		for(pthread = each_thread; pthread < each_thread + num_threads; pthread++) {
			if(pthread->done == true) {
				close(pthread->input);
				close(pthread->output);
				if(!work_left) {
					pthread->terminated = true;
					pthread->done = false;
					pthread_cancel(pthread->thread_info);
				} else {
					work_left--;
					pthread->input = open("/dev/zero", O_RDONLY);
					pthread->output = open("/dev/null", O_WRONLY);
					pthread->done = false;
					pthread->bytes = size;
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
			printf("work left = %d\n", work_left);	
			exit(0);

		}
	}

}
				

static void do_work(void)
{
	if(true == run_dev_zero)
		threads_zero_to_null();
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



