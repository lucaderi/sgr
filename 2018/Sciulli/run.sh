#!/bin/sh

if [[ ! $# == 1 ]]; then
echo "usage $0 and dir_name"
exit 1
fi
cd "$1"
./autogen.sh
./configure
make 
cd tests
./do.sh 
