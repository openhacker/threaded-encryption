#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <threads.h>
#include <assert.h>
#include "buffer_manager.h"

struct buffer {
	unsigned char *input;
	unsigned char *output;
	int size;
	int num_buffers;
};


static thread_local struct buffer *thread_buffer;



bool create_buffers(int size, int num_per_thread)
{
	printf("create buffers %d\n", gettid());
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
	printf("%s: %d\n", __func__, gettid());
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



