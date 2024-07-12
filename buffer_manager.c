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
	struct timeval read_cumulative;
	struct timeval write_cumulative;
	int num_writes;
	int num_reads;
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
	timeradd(&thread_buffer->write_cumulative, &delta, &thread_buffer->write_cumulative);
	thread_buffer->num_writes++;

	return ret_val;
}

int read_buffer(int fd, unsigned char *buffer, int size)
{
	return read(fd, buffer, size);
}

int write_times(struct timeval *sum)
{
	int ret;

	ret = thread_buffer->num_writes;
	thread_buffer->num_writes = 0;
	*sum = thread_buffer->write_cumulative;
	memset(&thread_buffer->write_cumulative,  0, sizeof(struct timeval));
	return ret;
}
	

