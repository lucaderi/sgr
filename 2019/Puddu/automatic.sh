#!/bin/bash
NDPIDEST=../src/lib

#file to copy to ndpi library
cp ndpi_wrap.c $NDPIDEST
if [ $? -ne 0 ]
then
    exit 1
fi
#assume the other one we will correct if the first ne have success
cp ndpi_example.py $NDPIDEST
cp ndpi_typestruct.py $NDPIDEST
cp Makefile.wrap $NDPIDEST

cd $NDPIDEST

make -f Makefile.wrap