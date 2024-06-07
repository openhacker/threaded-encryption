#! /bin/bash

DIRECTORY=/usr/local/space/3000

export REPORT_SPEED=1
set -e

ls -l $DIRECTORY

for i in 1 2 3 4
do
	./zero_files $i
done

for i in 1 2 3 4
do
	./encrypt_files -E -d $DIRECTORY -n -t $i
done

for i in 1 2 3 4
do
	./encrypt_files -E -d $DIRECTORY  -t $i
	./encrypt_files -D -d $DIRECTORY -t $i
done

