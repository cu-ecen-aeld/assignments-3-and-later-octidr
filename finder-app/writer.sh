#!/bin/sh
if [ -z "$1" ] || [ -z "$2" ]
then
    echo "ERROR:Usage ./writer.sh <write_file> <write_str>"
    exit 1
else
    writefile=$1
    writestr=$2
fi

mkdir -p "$(dirname "$writefile")"
echo "$writestr" > "$writefile"

if [ $? -ne 0 ]
then
    echo "ERROR: Could not create file $writefile"
    exit 1
fi