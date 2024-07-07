#! /bin/bash

DIRECTORY=/usr/local/tmp/100
export REPORT_SPEED=1

function drop_caches
{
	echo 3 | sudo tee /proc/sys/vm/drop_caches  >/dev/null
}

echo no drop caches, readahead




for threads in 1 2 
do
	
	 ./encrypt_files  -E -t $threads  -d /usr/local/tmp/100
	 export NO_HEADING=1
	 ./encrypt_files  -D  -t $threads -d /usr/local/tmp/100
done


echo drop caches, readahead
unset NO_HEADING


for threads in 1 2 
do
	drop_caches
	 ./encrypt_files  -E -t $threads  -d /usr/local/tmp/100
	 export NO_HEADING=1
	 drop_caches
	 ./encrypt_files  -D  -t $threads -d /usr/local/tmp/100
done

echo drop cached, no readahead
unset NO_HEADING
export NO_READAHEAD=1


for threads in 1 2 
do
	drop_caches
	 ./encrypt_files  -E -t $threads  -d /usr/local/tmp/100
	 export NO_HEADING=1
	 drop_caches
	 ./encrypt_files  -D  -t $threads -d /usr/local/tmp/100
done

