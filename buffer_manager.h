#ifndef _BUFFER_MANAGER
#define _BUFFER_MANAGER

#include <sys/time.h>

struct io_times {
	struct timeval read_cumulative;
	struct timeval write_cumulative;
	int num_writes;
	int num_reads;
	int bytes_written;
	int bytes_read;
};


bool create_buffers(int size, int num_per_thread);
void destroy_buffers(void);
unsigned char *get_inbuf(void);
unsigned char *get_outbuf(void);
int get_buffer_size(void);
int write_buffer(int fd, unsigned char *buffer, int size);
int read_buffer(int fd, unsigned char *buffer, int size);
// int write_times(struct timeval *sum);
void retrieve_io_times(struct io_times *io_times);

#endif
