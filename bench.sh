#! /bin/bash

# added $SYNC environment (to enable syncs do SYNC=-S
# set the environment DIRECTORY to run benchmark on a different place.
# example:
#   DIRECTORY=/raid/raid0/1k ./bench.sh

: "${DIRECTORY:=/media/leisner/space/1k}"



# so easy to remove
function clear_cache
{
	./clear-cache
}

export IO_TIMES=1

max_threads=3
buffer_sizes=" $(( 5 * 1024 ))    $(( 64 * 1024 ))   $((1024 * 1024))"


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

echo -e '\nno write on filesystem'
for i in $(seq 1 $max_threads)
do
	if [[ $first -gt 0 ]]; then
		export NO_HEADING=1
	fi
	clear_cache
	./encrypt_files -E -d $DIRECTORY -n -t $i
	first=1
done


unset NO_HEADING

first=0

echo -e "\nno write on filesystem (no readahead)"
export NO_READAHEAD=1
for i in $(seq 1 $max_threads)
do
	if [[ $first -gt 0 ]]; then
		export NO_HEADING=1
	fi
	clear_cache
	./encrypt_files -E -d $DIRECTORY -n -t $i
	first=1
done

first=0
unset NO_HEADING
echo

unset NO_READAHEAD
echo -e  "\nread/write encryption/decryption"

for size in $buffer_sizes
do
	echo buffer = $size
	for i in $(seq 1 $max_threads)
	do
		clear_cache
		./encrypt_files  ${SYNC} -E -d $DIRECTORY  -t $i -b $size
		first=1
		if [[ $first -gt 0 ]]; then
			export NO_HEADING=1
		fi
		clear_cache
		./encrypt_files ${SYNC} -D -d $DIRECTORY -t $i -b $size
	done
done


echo -e  "\nread/write encryption/decryption (NO_READAHEAD)"
export NO_READAHEAD=1

for i in $(seq 1 $max_threads)
do
	clear_cache
	./encrypt_files ${SYNC} -E -d $DIRECTORY  -t $i
	first=1
	if [[ $first -gt 0 ]]; then
		export NO_HEADING=1
	fi
	clear_cache
	./encrypt_files ${SYNC} -D -d $DIRECTORY -t $i
done
echo took to run $SECONDS  seconds
