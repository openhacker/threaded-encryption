#include <stdio.h>
#include <pthread.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "openssl_threads.h"


static  pthread_mutex_t able_to_condition = PTHREAD_MUTEX_INITIALIZER;
static  pthread_cond_t cv = PTHREAD_COND_INITIALIZER;

struct thread_info {
	struct thread_entry *work;
	pthread_t info; 
	pthread_mutex_t work_available;
	bool done;	/* work is done */
	bool terminated;	/* thread doesn't exist anymore */
};



static struct thread_info *thread_info;
static int num_threads;

#if 0
static  pthread_mutex_t able_to_condition = PTHREAD_MUTEX_INITIALIZER;
static  pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
#endif

static  pthread_mutex_t able_to_condition;
static  pthread_cond_t cv;

static void create_thread_structure(int thread_count)
{
	pthread_mutex_init(&able_to_condition, NULL);
	pthread_cond_init(&cv, NULL);
	num_threads = thread_count;
	thread_info = calloc(sizeof(struct thread_info), num_threads);
	

}

static void *encrypt_decrypt(void *args)
{
	struct thread_info *info = (struct thread_info *) args;

	while(1) {
		bool bool_result = false;
		struct thread_entry *current_work;

		pthread_mutex_lock(&info->work_available);
		current_work = info->work;

		if(current_work->encrypt == true) {
			current_work->encrypt_status = do_encrypt(current_work->input_file, current_work->output_file, 
					current_work->size, current_work->aes_key);
		} else {
			current_work->decrypt_status = do_decrypt(current_work->input_file, current_work->output_file,
								current_work->aes_key);
		}
		info->done = true;
		pthread_cond_broadcast(&cv);
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

	create_thread_structure(num_threads);

	/* spawn off threads  with work */
	for(pthread = thread_info, i =  0; i < num_threads && i < num_entries;  i++, pthread++) {
		int result;

		result = pthread_mutex_init(&pthread->work_available, NULL);

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

	pthread_mutex_lock(&able_to_condition);
	work_left -= num_threads;	

	for(pthread = thread_info; pthread < thread_info + num_threads; pthread++) {
		pthread_mutex_unlock(&pthread->work_available);
	}
		
	while(1) {
		pthread_cond_wait(&cv, &able_to_condition);
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
			}
		}
		
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

	return count;
		
}





