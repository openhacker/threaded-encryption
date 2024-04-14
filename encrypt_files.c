#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "openssl_threads.h"


static void usage(const char *string) 
{

	if(string)
		fprintf(stderr, "%s\n", string);
	printf("-d <directory>\n");
	printf("-t <num threads\n");
	printf("-n -- write to /dev/null\n");
	exit(1);
}

static char **find_files(const char *directory)
{
	FILE *stream;
	char command[300];
	char *output = NULL;
	char *output_tokens;
	int loop_times = 0;
	const int alloc_size = 1024;
	size_t bytes_read;
	int i = 0;

	snprintf(command, sizeof command, "find %s -type f", directory);


	stream = popen(command, "r");
	while(1) {
		size_t bytes;

		output = realloc(output, alloc_size * (loop_times + 1));
		bytes = fread(output + (loop_times * alloc_size), 1, alloc_size, stream);
		if(feof(stream))
			break;
		bytes_read += bytes;
		loop_times++;
	}
	pclose(stream);

	printf("output = %s\n", output);

	output_tokens = output;
	while(1) {
		char *token;

		token = strsep(&output_tokens, " \n");
		if(!token)
			break;
		printf("token %d = %s\n", i, token);
		i++;
	}

	free(output);
	
	return NULL;
}

int main(int argc, char *argv[])
{
	char *directory = NULL;
	int num_threads = 1;
	char **files;
	bool write_to_dev_null = false;

	while(1) {
		int c;

		c = getopt(argc, argv,  "d:nt:");
		if(c == -1)
			break;

		switch(c) {
			case 'd':
				directory = strdup(optarg);
				break;
			case 't':
				num_threads = atoi(optarg);
				break;
			case 'n':
				write_to_dev_null = true;
				break;
			case 'h':
				usage(NULL);
			default:
				usage("illegal argument");
		}
					

	}

	if(!directory) {
		usage("No directory selected");
	}


	files = find_files(directory);
	
	system("set -x; time -p sync");

}





