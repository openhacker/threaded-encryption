#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <threads.h>
#include <assert.h>
#include <sys/time.h>
#include <string.h>
#include "buffer_manager.h"

struct buffer {
	unsigned char *input;
	unsigned char *output;
	int size;
	int num_buffers;
	struct io_times io_times;
};


static thread_local struct buffer *thread_buffer;



bool create_buffers(int size, int num_per_thread)
{
	assert(num_per_thread == 1);
	thread_buffer = calloc(sizeof(struct buffer), 1);
	assert(thread_buffer);
	thread_buffer->input = malloc(size);
	assert(thread_buffer->input);
	thread_buffer->output = malloc(size + 16);	// 16 is magic increment
	assert(thread_buffer->output);
	thread_buffer->size = size;
	thread_buffer->num_buffers = num_per_thread;
	return true;

}

void destroy_buffers(void)
{
	assert(thread_buffer);
	free(thread_buffer->output);
	free(thread_buffer->input);
	free(thread_buffer);
}

unsigned char *get_inbuf(void)
{
	assert(thread_buffer);
	return thread_buffer->input;
}

unsigned char *get_outbuf(void)
{
	assert(thread_buffer);
	return thread_buffer->output;
}

int get_buffer_size(void)
{
	return thread_buffer->size;
}


/* ml -- invetigate if errno needs to be preserved */
int write_buffer(int fd, unsigned char *buffer, int size)
{
	int ret_val;
	struct timeval start;
	struct timeval end;
	struct timeval delta;

	gettimeofday(&start, NULL);
	ret_val = write(fd, buffer, size);
	gettimeofday(&end, NULL);
	timersub(&end, &start, &delta);
	timeradd(&thread_buffer->io_times.write_cumulative, &delta, &thread_buffer->io_times.write_cumulative);
	thread_buffer->io_times.num_writes++;

	return ret_val;
}

int read_buffer(int fd, unsigned char *buffer, int size)
{
	int ret_val;
	struct timeval start;
	struct timeval end;
	struct timeval delta;

	gettimeofday(&start, NULL);
	ret_val = read(fd, buffer, size);
	gettimeofday(&end, NULL);

	timersub(&end, &start, &delta);
//	printf("read = %ld.%06ld\n", delta.tv_sec, delta.tv_usec);

	timeradd(&thread_buffer->io_times.read_cumulative, &delta, &thread_buffer->io_times.read_cumulative);
	thread_buffer->io_times.num_reads++;

	return ret_val;
}

void retrieve_io_times(struct io_times *io_times)
{
	*io_times = thread_buffer->io_times;
	memset(&thread_buffer->io_times, 0, sizeof(struct io_times));
}
	

