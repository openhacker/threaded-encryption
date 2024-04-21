#include <stdio.h>
#include <pthread.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdatomic.h>
#include "openssl_threads.h"


struct thread_info {
	struct thread_entry *work;
	pthread_t info; 
	pthread_mutex_t work_available;
	bool done;	/* work is done */
	bool terminated;	/* thread doesn't exist anymore */
};



/* use pipe trick for sychronization.
 * Write says a thread is finished.
 * Read after a thread is finished.
 * The done flag is used after the work is done
 * The terminated flag is used when the thread went away.
 */
static int pipe_fds[2];

static struct thread_info *thread_info;
static int num_threads;

static atomic_int num_atomic_condition;
static int num_condition;


static bool create_thread_structure(int thread_count)
{
	int result;

	num_threads = thread_count;
	thread_info = calloc(sizeof(struct thread_info), num_threads);


	result  = pipe(&pipe_fds);
	if(result < 0) {
		fprintf(stderr, "problem creating pipe: %s\n", strerror(errno));
		return false;
	}

	return true;	

}

static void *encrypt_decrypt(void *args)
{
	struct thread_info *info = (struct thread_info *) args;
//	bool first_time = true;

	while(1) {
		struct thread_entry *current_work;
		char byte = 0;
		int result;

		pthread_mutex_lock(&info->work_available);

#if 0
		if(true == first_time) {
			usleep(10000);
			first_time = false;
		}
#endif
		current_work = info->work;

		if(current_work->encrypt == true) {
			current_work->encrypt_status = do_encrypt(current_work->input_file, current_work->output_file, 
					current_work->size, current_work->aes_key);
		} else {
			current_work->decrypt_status = do_decrypt(current_work->input_file, current_work->output_file,
								current_work->aes_key);
		}
		info->done = true;

		num_atomic_condition++;
		num_condition++;
		result = write(pipe_fds[1], &byte, 1);
		if(result < 0) {
			fprintf(stderr, "cannot write %s\n", strerror(errno));
			return NULL;
		}


	}

	return NULL;
}


static int get_file_size(const char *file)
{
	struct stat statbuf;
	int result;

	result = stat(file, &statbuf);
	if(result < 0) {
		fprintf(stderr, "stat on %s is problem: %s\n", file, strerror(errno));
		return -1;
	}
	return statbuf.st_size;
}



int openssl_with_threads(struct thread_entry *array, 
		int num_entries, 
		int num_threads,
		bool  (*callback)(struct thread_entry *entry))
{
	int i;
	int jobs_processed;
	struct thread_info *pthread;
	int work_left = num_entries;
	int count = 0;
	int num_condition = 0;


	if(num_threads < 1) 
		return 0;

	if(false == create_thread_structure(num_threads))
		return 0;	/* problem created structure */

	/* spawn off threads  with work */
	for(pthread = thread_info, i =  0; i < num_threads && i < num_entries;  i++, pthread++) {
		int result;

		pthread_mutex_init(&pthread->work_available, NULL);
		result = pthread_mutex_lock(&pthread->work_available);

		assert(result == 0);

		pthread->done = false;
		pthread->work = array + i;

		result = pthread_create(&pthread->info, NULL,  encrypt_decrypt, pthread);
		assert(result == 0);
	}

	/* case where less files than threads */
	if(i  <  num_threads) 
		num_threads = i;	

	work_left -= num_threads;	

	for(pthread = thread_info; pthread < thread_info + num_threads; pthread++) {
		pthread_mutex_unlock(&pthread->work_available);
	}
		
	while(num_condition < num_entries) {
		int result;
		char c;

		result = read(pipe_fds[0], &c, 1);
		switch(result) {
			case 0:
				fprintf(stderr, "pipe closed\n");
				return num_condition;	// cleanup??
			case 1:
				break;
			case -1:
				fprintf(stderr, "read pipe error: %s\n", strerror(errno));
				continue;
		}

		num_condition++;

		/* see if we need to callback, note this is done and see if more work is needed for the thread */
		for(pthread = thread_info; pthread < thread_info + num_threads; pthread++) {
			if(pthread->done == true) {
				struct thread_entry *pentry;

				count++;
				pentry = pthread->work;
				if(!pentry->size) {
					if(pentry->encrypt)
						pentry->size = get_file_size(pentry->input_file);
					else	pentry->size = get_file_size(pentry->output_file);
				}
				if(callback) 
					(*callback)(pentry);
				if(work_left > 0) {
					pthread->work = array + (num_entries - work_left);
					pthread_mutex_unlock(&pthread->work_available);
					work_left--;
				} else { 
					// no more work for thread
					pthread_cancel(pthread->info);
					pthread->terminated = true;
				}
				pthread->done = false;
				break;
			}
		}

		assert(pthread < thread_info + num_threads);

		bool not_terminated = false;

		/* if all threads terminated, exit */
		for(pthread = thread_info; pthread < thread_info + num_threads; pthread++) {
			if(pthread->terminated == false) {
				not_terminated = true;
				break;
			} 
		}

		if(not_terminated == false) {
			break;
		}
	}
	close(pipe_fds[0]);
	close(pipe_fds[1]);
	free(thread_info);

	return count;
		
}





