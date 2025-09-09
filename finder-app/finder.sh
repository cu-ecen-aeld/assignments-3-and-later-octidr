#!/bin/sh
if [ -z "$1" ] || [ -z "$2" ]
then
    echo "ERROR:Usage ./finder.sh <files_dir> <search_str>"
    exit 1
else
    filesdir=$1
    searchstr=$2
fi

if [ ! -d "$filesdir" ]
then
    echo "ERROR: $filesdir is not a valid directory path"
    exit 1
fi

# Assume we don't care about files in subdirectories
numfiles="$(ls "$filesdir" | wc -l)"
numlines="$(grep "$searchstr" "$filesdir"/* | wc -l)"

echo "The number of files are $numfiles and the number of matching lines are $numlines"