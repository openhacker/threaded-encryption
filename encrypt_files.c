#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <limits.h>
#include <assert.h>
#include <string.h>
#include <sys/time.h>
#include "openssl_threads.h"

static const uint8_t default_key[AES_256_KEY_SIZE] = { 0 };
static const uint8_t alternate_key[AES_256_KEY_SIZE] = { "this is another key" };

static long int total_bytes;

static bool show_callback = false;

static struct timeval start_time;


static void usage(const char *string) 
{

	if(string)
		fprintf(stderr, "%s\n", string);
	printf("\t-d <directory>\n");
	printf("\t-t <num threads\n");
	printf("\t-E     encrypt (default)\n");
	printf("\t-D     decrypt\n");
	printf("\t-C     copy\n");
	printf("\t-n     write to /dev/null (for benchmarking)\n");
	printf("\t-s     show each callback\n");
	printf("\t-o     output directory (infers $NO_DELETE)\n");
	printf("\t-a	 alternate builtin key (to test failure)\n");
	printf("\t-S     perform sync at end\n");
	printf("\t-b <buffer size>\n");
	exit(1);
}

static const char *stringize_operation(enum openssl_operation op)
{
	switch(op) {
		case OP_ENCRYPT:
			return "encrypt";
		case OP_DECRYPT:
			return "decrypt";
		case OP_COPY:
			return "copy";
		default:
			return "unknown operation";
	}
}

static bool callback(struct thread_entry *pentry, enum openssl_operation op, size_t size )
{
	static int count = 0;

	if(true == show_callback)  {
		const char *type_string;

		type_string = stringize_operation(op);

		fprintf(stderr, "file %d: %s %s to %s = %ld bytes\n", count++,  type_string,
				pentry->input_file, pentry->output_file, size);
	}

	switch(op) {
		case OP_ENCRYPT:
			if(pentry->encrypt_status != ENCRYPT_SUCCESSFUL) {
		       		fprintf(stderr, "problem with %s, encrypt not successful = %d\n",
			 			pentry->input_file, pentry->encrypt_status);
				return false;
 			}
			break;
		case OP_DECRYPT:
			if(pentry->decrypt_status != DECRYPT_SUCCESSFUL) {
				fprintf(stderr, "problem with %s, decrypt not successful = %d\n",
						pentry->input_file, pentry->decrypt_status);
				return false;
			}
			break;
		case OP_COPY:
			break;
		default:
			fprintf(stderr, "Problem with op in %s\n", __func__);
			break;
	}

	total_bytes += size;

	return true;
}

static char **find_files(const char *directory)
{
	FILE *stream;
	char command[PATH_MAX];
	char *output = NULL;
	char *output_tokens;
	int loop_times = 0;
	const int alloc_size = 1024;
	size_t bytes_read;
	int i = 0;
	int string_size __attribute__((unused)) ;
	char **files = NULL;

	snprintf(command, sizeof command, "cd %s; find . -type f", directory);


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
	int num_elements =0;
	struct thread_entry *entries;
	int result;
	enum openssl_operation op = OP_ENCRYPT;
	char *output_directory = NULL;
	const uint8_t *key_to_use = default_key;
	bool add_sync = false;

	while(1) {
		int c;

		c = getopt(argc, argv,  "SasDCEd:nt:o:b:");
		if(c == -1)
			break;

		switch(c) {
			case 'b':
				buffer_size = strtol(optarg, NULL, 10);
				break;
			case 'd':
				directory = strdup(optarg);
				break;
			case 't':
				num_threads = atoi(optarg);
				break;
			case 'S':
				add_sync = true;
				break;
			case 's':
				show_callback = true;
				break;
			case 'n':
				write_to_dev_null = true;
				setenv("NO_DELETE", "1", 1);
				break;
			case 'h':
				usage(NULL);
			case 'E':
				op = OP_ENCRYPT;
				break;
			case 'D':
				op = OP_DECRYPT;
				break;
			case 'C':
				op = OP_COPY;
				break;
			case 'o':
				output_directory = strdup(optarg);
				setenv("NO_DELETE", "1", 1);
				break;
			case 'a':
				printf("Using alternate key\n");
				key_to_use = alternate_key;
				break;
			default:
				usage("illegal argument");
		}
					

	}

	if(!directory) {
		usage("No directory selected");
	}

	if(!output_directory)
		output_directory = directory;


	files = find_files(directory);


	for(char **walker = files; *walker; walker++) {
//		printf("entry = %s\n", *walker);
		num_elements++;
	}

	entries = calloc(sizeof *entries, num_elements);

	for(int i = 0; i < num_elements; i++) {
		struct thread_entry *pentry;
		char input_file[PATH_MAX];

		pentry = &entries[i];
		snprintf(input_file, sizeof input_file, "%s/%s", directory, files[i]);
		pentry->input_file = strdup(input_file);

		if(true == write_to_dev_null) {
			pentry->output_file = strdup("/dev/null");
		} else {
			char temp_buffer[PATH_MAX];
			char input_buffer[PATH_MAX];
			char *base;
			char *dir;

			strcpy(input_buffer, files[i]);

			base = basename(input_buffer);
			dir = dirname(input_buffer);
			assert(dir);
			assert(base);
			
//			printf("dir = %s, base = %s\n", dir, base);

			if(op == OP_ENCRYPT || op == OP_COPY) {

				snprintf(temp_buffer, sizeof temp_buffer, "%s/%s/%s.hypn", 
							output_directory, dir, base);
				pentry->output_file = strdup(temp_buffer);
			} else if(op == OP_DECRYPT) {
				char *suffix;

				suffix = strrchr(base, '.');
				if(!suffix) {
					fprintf(stderr, "No trailing .\n");
					abort();
				}
				*suffix = '\0';
				snprintf(temp_buffer, sizeof temp_buffer, "%s/%s/%s",
					       	output_directory, dir, base);
				pentry->output_file = strdup(temp_buffer);
			}
				
		}
	}

	result = openssl_with_threads(entries, num_elements, num_threads, key_to_use, op, callback); 

//	printf("result = %d\n", result);
//      printf("bytes processed = %ld\n", total_bytes);
	
	if(true == add_sync)
		system("command time -f \"sync %e seconds\"  sync");

}





