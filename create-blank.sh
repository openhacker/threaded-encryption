#! /bin/bash


NUMBER=${1:-3000}

for i in $(seq $NUMBER)
do
       dd if=/dev/zero of=$i  bs=16k count=750
#         dd if=/dev/zero of=$i  bs=16k count=7
done


