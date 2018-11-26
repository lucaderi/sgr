#!/bin/sh

cd nDPI-dev
./autogen.sh
./configure
make 
cd tests
./do.sh 
