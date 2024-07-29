#! /bin/bash

# DIRECTORY=/usr/local/tmp/100
DIRECTORY=/raid/linux/tmp/100

export REPORT_SPEED=1

function drop_caches
{
	echo 3 | sudo tee /proc/sys/vm/drop_caches  >/dev/null
}



echo $(hostname)  size of directory = $(du -s -h $DIRECTORY)

echo -e '\n no drop caches, readahead'



for threads in 1 2 
do
	
	 ./encrypt_files  -E -t $threads  -d $DIRECTORY
	 export NO_HEADING=1
	 ./encrypt_files  -D  -t $threads -d $DIRECTORY
done


echo -e  '\n drop caches, readahead'
unset NO_HEADING
    
 
for threads in 1 2 
do
	drop_caches
	 ./encrypt_files  -E -t $threads  -d $DIRECTORY
	 export NO_HEADING=1
	 drop_caches
	 ./encrypt_files  -D  -t $threads -d $DIRECTORY
done

echo -e '\n drop caches no readahead'
unset NO_HEADING
export NO_READAHEAD=1


for threads in 1 2 
do
	drop_caches
	 ./encrypt_files  -E -t $threads  -d $DIRECTORY
	 export NO_HEADING=1
	 drop_caches
	 ./encrypt_files  -D  -t $threads -d $DIRECTORY
done

echo -e '\n drop caches, no readahead, changing buffers'
unset NO_HEADING

for buffer_size in $(( 5 * 1024 ))   $(( 64 * 1024 ))   $(( 1024 * 1024 ))
do
	echo buffer_size = $buffer_size
	for threads in 1 2 
	do
		drop_caches
		 ./encrypt_files  -E -t $threads  -b $buffer_size -d $DIRECTORY
		 export NO_HEADING=1
		 drop_caches
		 ./encrypt_files  -D  -t $threads -b $buffer_size -d $DIRECTORY
	done
done
	

echo -e '\n drop caches, readahead, changing buffers'

unset NO_HEADING
unset NO_READAHEAD



for buffer_size in $(( 5 * 1024 ))   $(( 64 * 1024 ))   $(( 1024 * 1024 ))
do
	echo buffer_size = $buffer_size
	for threads in 1 2 
	do
		drop_caches
		 ./encrypt_files  -E -t $threads  -b $buffer_size -d $DIRECTORY
		 export NO_HEADING=1
		 drop_caches
		 ./encrypt_files  -D  -t $threads -b $buffer_size -d $DIRECTORY
	done
done
