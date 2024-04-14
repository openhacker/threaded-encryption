#include <stdio.h>
#include <pthread.h>
#include <assert.h>
#include <stdlib.h>
#include "openssl_threads.h"


static  pthread_mutex_t able_to_condition = PTHREAD_MUTEX_INITIALIZER;
static  pthread_cond_t cv = PTHREAD_COND_INITIALIZER;

struct thread_info {
	struct thread_entry *work;
	pthread_t info; 
	pthread_mutex_t work_available;
	bool done;
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
			info->done = true;
			pthread_cond_broadcast(&cv);
		} else {
			abort();
		}
	}

	return NULL;
}


int openssl_with_threads(struct thread_entry *array, 
		int num_entries, 
		int num_threads,
		unsigned char aes_key[32],	/* for AES 256 */
		bool  (*callback)(struct thread_entry *entry, size_t size))
{
	int i;
	int jobs_processed;
	struct thread_info *pthread;


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
		
}





