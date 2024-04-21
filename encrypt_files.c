#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "openssl_threads.h"

static const uint8_t default_key[AES_256_KEY_SIZE] = { 0 };


static long int total_bytes;
static bool encrypt = true;	

static bool show_callback = true;

static void usage(const char *string) 
{

	if(string)
		fprintf(stderr, "%s\n", string);
	printf("\t-d <directory>\n");
	printf("\t-t <num threads\n");
	printf("\t-E encrypt (default)\n");
	printf("\t-D decrypt\n");
	printf("-n -- write to /dev/null\n");
	exit(1);
}

static bool callback(struct thread_entry *pentry)
{
	static int count = 0;

	if(true == show_callback)  {
		fprintf(stderr, "file %d: %s %s to %s = %d bytes\n", count++,  encrypt ? "encrypted" : "decrypted",
				pentry->input_file, pentry->output_file, pentry->size);
	}

	if(pentry->encrypt == true) {
		if(pentry->encrypt_status != ENCRYPT_SUCCESSFUL) {
		       fprintf(stderr, "problem with %s, encrypt not successful = %d\n",
			 		pentry->input_file, pentry->encrypt_status);
			return false;
 		}
	} else {
		if(pentry->decrypt_status != DECRYPT_SUCCESSFUL) {
			fprintf(stderr, "problem with %s, decrypt not successful = %d\n",
					pentry->input_file, pentry->decrypt_status);
			return false;
		}
	}
	total_bytes += pentry->size;

	return true;
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
	int string_size;
	char **files = NULL;

	snprintf(command, sizeof command, "find %s -type f", directory);


	stream = popen(command, "r");
	while(1) {
		size_t bytes;

		output = realloc(output, alloc_size * (loop_times + 1));
		memset(output + (loop_times * alloc_size), 0, alloc_size);
		bytes = fread(output + (loop_times * alloc_size), 1, alloc_size, stream);
		if(feof(stream))
			break;
		bytes_read += bytes;
		loop_times++;
	}
	pclose(stream);


	string_size = strlen(output);
	// printf("bytes = %d, output = %s\n", string_size, output);

	output_tokens = output;
	while(1) {
		char *token;

		token = strsep(&output_tokens, "\n");
		if(!token || !*token)
			break;


//		printf("token %d = %s\n", i, token);
		files = realloc(files, sizeof (char **) * (i + 1));
		files[i] = strdup(token);
		i++;
	}

	files = realloc(files, sizeof(char **) * (i + 1));
	files[i] = NULL;
	free(output);
	
	return files;
}

int main(int argc, char *argv[])
{
	char *directory = NULL;
	int num_threads = 1;
	char **files;
	bool write_to_dev_null = false;
	char *cp;
	int num_elements =0;
	struct thread_entry *entries;
	int result;

	while(1) {
		int c;

		c = getopt(argc, argv,  "DEd:nt:");
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
			case 'E':
				encrypt = true;
				break;
			case 'D':
				encrypt = false;
				break;
			default:
				usage("illegal argument");
		}
					

	}

	if(!directory) {
		usage("No directory selected");
	}

	files = find_files(directory);


	for(char **walker = files; *walker; walker++) {
//		printf("entry = %s\n", *walker);
		num_elements++;
	}

	entries = calloc(sizeof *entries, num_elements);

	for(int i = 0; i < num_elements; i++) {
		char temp_buffer[PATH_MAX];
		struct thread_entry *pentry;

		pentry = &entries[i];
		strcpy(pentry->input_file, files[i]);
		if(true == write_to_dev_null) {
			strcpy(pentry->output_file, "/dev/null");
		} else {
			snprintf(temp_buffer, sizeof temp_buffer, "%s.hypn", files[i]);
			strcpy(pentry->output_file, temp_buffer);
		}
		pentry->encrypt = true;
		memcpy(pentry->aes_key, default_key, sizeof default_key);
	}

	result = openssl_with_threads(entries, num_elements, num_threads, callback); 

	printf("result = %d\n", result);
	printf("bytes processed = %ld\n", total_bytes);
	
	system("set -x; time -p sync");

}





