#include <stdio.h>
#include <pthread.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/resource.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdatomic.h>
#include "openssl_threads.h"


struct thread_info {
	struct thread_entry *work;
	pthread_t info; 
	pthread_mutex_t work_available;
	bool done;	/* work is done */
	bool terminated;	/* thread doesn't exist anymore */
	uint8_t *input_buffer;	/* malloced data */
	uint8_t *output_buffer;	/* malloced data */
};



static uint8_t AES_key[AES_256_KEY_SIZE];
static enum openssl_operation op_type;
static const size_t derived_size = 1024 * 1024 * 1024;  // for OP_COPY and /dev/zero
static size_t file_size = 0;

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

	result  = pipe(pipe_fds);
	if(result < 0) {
		fprintf(stderr, "problem creating pipe: %s\n", strerror(errno));
		return false;
	}

	return true;	

}

static void *encrypt_decrypt(void *args)
{
	struct thread_info *info = (struct thread_info *) args;

	while(1) {
		struct thread_entry *current_work;
		char byte = 0;
		int result;

		pthread_mutex_lock(&info->work_available);

		current_work = info->work;

		switch(op_type) {
			case OP_ENCRYPT:
				current_work->encrypt_status = do_encrypt(current_work->input_file, current_work->output_file, 
					file_size, AES_key );
				break;
			case OP_DECRYPT:
				current_work->decrypt_status = do_decrypt(current_work->input_file, current_work->output_file,
								AES_key);
				break;
			default:
				fprintf(stderr, "whoops\n");
				abort();
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



static bool do_unlink(const char *name)
{
	int result;

	result = unlink(name);

	if(result < 0) {
		fprintf(stderr, "cannot unlink %s: %s\n", name, strerror(errno));
		return false;
	}
	return true;
}



static double timeval_to_seconds(struct timeval t)
{
	double seconds;

	seconds = t.tv_sec;
	seconds += t.tv_usec / (1000.0 * 1000.0);

	return seconds;
}

int openssl_with_threads(struct thread_entry *array, 
		int num_entries, 
		int num_threads,
		const uint8_t parm_AES_key[AES_256_KEY_SIZE],
		enum openssl_operation type,
		bool  (*callback)(struct thread_entry *entry, enum openssl_operation op_type, size_t size) )
{
	int i;
	int jobs_processed = 0;
	struct thread_info *pthread;
	int work_left = num_entries;
	int count = 0;
	int num_files_ended = 0;
	bool delete_files = true;
	size_t bytes_processed = 0;
	struct timeval start_time;
       	struct timeval	end_time;
	struct rusage start_rusage;
	struct rusage end_rusage;
//	struct timeval delta_time;
	double seconds;
	bool report_speed = false;
	bool found_thread_end = false;


	if(num_threads < 1) 
		return 0;


	memcpy(AES_key, parm_AES_key, sizeof AES_key);

	if(getenv("NO_DELETE"))
		delete_files = false;
	
	if(getenv("REPORT_SPEED"))
		report_speed = true;

	if(false == create_thread_structure(num_threads))
		return 0;	/* problem created structure */

	gettimeofday(&start_time, NULL);
	getrusage(RUSAGE_SELF, &start_rusage);

	op_type =  type;
	if(getenv("DEV_ZERO"))
		file_size = derived_size;
	else	file_size = 0;

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

	jobs_processed +=  num_threads;
	work_left -= num_threads;	

	for(pthread = thread_info; pthread < thread_info + num_threads; pthread++) {
		pthread_mutex_unlock(&pthread->work_available);
	}
		
	while(num_files_ended <= num_entries) {
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

		num_files_ended++;

		/* see if we need to callback, note this is done and see if more work is needed for the thread */
		for(pthread = thread_info; pthread < thread_info + num_threads; pthread++) {
			if(pthread->done == true) {
				struct thread_entry *pentry;
				int size = 0;

				found_thread_end = true;
				count++;
				pentry = pthread->work;
				switch(op_type)  {
					case OP_ENCRYPT:
						if(file_size)
							size = derived_size;
						else  {
							/* cannot delete derived files like /dev/zero */
							size = get_file_size(pentry->input_file);
							if(true == delete_files) {
								if(pentry->encrypt_status == ENCRYPT_SUCCESSFUL) {
									do_unlink(pentry->input_file);
								} else do_unlink(pentry->output_file);
							}
						}
						break;
					case OP_DECRYPT:
						size = get_file_size(pentry->output_file);
						if(true == delete_files) {
							if(pentry->decrypt_status == DECRYPT_SUCCESSFUL) {
								do_unlink(pentry->input_file);
							} else do_unlink(pentry->output_file);
						}	
						break;
					case OP_COPY:
						size = derived_size;
						break;
				}

				bytes_processed += size;

				if(callback)  {
					bool stop;
					stop = (*callback)(pentry, op_type, size);

					if(stop == false) {
						fprintf(stderr, "want to stop\n");
					}
				}

				pthread->done = false;
				if(work_left > 0) {
					pthread->work = array + (num_entries - work_left);
					pthread_mutex_unlock(&pthread->work_available);
					work_left--;
					jobs_processed++;
				} else { 
					// no more work for thread
					pthread_cancel(pthread->info);
					pthread->terminated = true;
				}
				break;
			}
		}

		if(false == found_thread_end) {
			printf("didn't find thread end: count = %d, jobs_processed = %d, work_left = %d\n",
				       			count, jobs_processed, work_left);
			continue;
		}
//		assert(pthread < thread_info + num_threads);

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
		found_thread_end = false;
	}


	gettimeofday(&end_time, NULL);
	getrusage(RUSAGE_SELF, &end_rusage);

	close(pipe_fds[0]);
	close(pipe_fds[1]);
	/* destroy mutexes  for each thread */
	free(thread_info);

	if(true == report_speed) {
		struct timeval delta_time;
		struct timeval delta_usertime;
		struct timeval delta_systime;

		timersub(&end_time, &start_time, &delta_time);
		seconds = delta_time.tv_sec;
		seconds += delta_time.tv_usec / (1000.0 * 1000.0);
		printf("bandwidth = %.3f G/sec\n", ((bytes_processed) / (1024.0 * 1024.0 * 1024.0))  / seconds);
		timersub(&end_rusage.ru_utime, &start_rusage.ru_utime, &delta_usertime);
		timersub(&end_rusage.ru_stime, &start_rusage.ru_stime, &delta_systime);
		printf("wall time =  %.3f user time = %.3f, systime = %.3f\n",
			timeval_to_seconds(delta_time), timeval_to_seconds(delta_usertime), timeval_to_seconds(delta_systime));
		
		
	}


	return count;
		
}



