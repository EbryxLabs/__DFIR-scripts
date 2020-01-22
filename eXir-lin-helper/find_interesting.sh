#!/bin/bash

# Example
# /bin/bash script.sh /path/to/patterns_file /path/to/target/file

# Example for secure file
# grep -r -o -E "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"

patterns_file=$1;
target_file=$2;
temp_file="test_`date +%s-%N`.txt";

grep --color=always -i -n -r -E -f $patterns_file $target_file;
# grep --color=always -i -n -r -E -f $patterns_file $target_file | tee -a $temp_file > /dev/null 2>&1;
# zgrep --color=always -i -n -f $patterns_file $target_file | tee -a $temp_file > /dev/null 2>&1;

# only gather unique names from the file 
# cat $temp_file | uniq;
# cat $temp_file;
# rm $temp_file;