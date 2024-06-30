#ifndef _BUFFER_MANAGER
#define _BUFFER_MANAGER

bool create_buffers(int size, int num_per_thread);
void destroy_buffers(void);
unsigned char *get_inbuf(void);
unsigned char *get_outbuf(void);

#endif
