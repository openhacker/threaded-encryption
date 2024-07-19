#! /bin/bash

# DIRECTORY=/usr/local/space/3000

# DIRECTORY=/media/leisner/encrypt-spac/100
# DIRECTORY=/raid/linux/tmp/5k
DIRECTORY=/media/leisner/space/1k

max_threads=2


echo $(hostname) using  $(du -s -h $DIRECTORY)
export REPORT_SPEED=1
set -e

first=0

echo 'zero_files (in core encrption)'
for i in $(seq 1 $max_threads)
do
	if [[ $first -gt 0 ]]; then
		export NO_HEADING=1
	fi
	./zero_files -t $i
	first=1
done


unset NO_HEADING
echo

first=0

echo no write on filesystem
for i in $(seq 1 $max_threads)
do
	if [[ $first -gt 0 ]]; then
		export NO_HEADING=1
	fi
	./clear-cache
	./encrypt_files -E -d $DIRECTORY -n -t $i
	first=1
done

echo -e "\nno write (no readahead)\n"

unset NO_HEADING
echo

first=0

echo -e "\nno write on filesystem (no readahead)\n"
export NO_READAHEAD=1
for i in $(seq 1 $max_threads)
do
	if [[ $first -gt 0 ]]; then
		export NO_HEADING=1
	fi
	./clear-cache
	./encrypt_files -E -d $DIRECTORY -n -t $i
	first=1
done

first=0
unset NO_HEADING
echo

unset NO_READAHEAD
echo -e  "read/write encryption/decryption\n"

for i in $(seq 1 $max_threads)
do
	./clear-cache
	./encrypt_files -E -d $DIRECTORY  -t $i
	first=1
	if [[ $first -gt 0 ]]; then
		export NO_HEADING=1
	fi
	./clear-cache
	./encrypt_files -D -d $DIRECTORY -t $i
done

