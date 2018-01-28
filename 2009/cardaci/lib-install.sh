#!/bin/bash

pushd libmicrohttpd-0.3.1
./configure --prefix=/tmp/
make
make install
popd
