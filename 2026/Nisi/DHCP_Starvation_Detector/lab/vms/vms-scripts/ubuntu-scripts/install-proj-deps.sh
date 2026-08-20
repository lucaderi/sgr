#!/bin/sh

# Install all the dependencies for the project.
sudo apt update && sudo apt install -y \
  gcc make libpcap-dev rrdtool \
  libnetconf2-dev libyang-dev libssh-dev \
  sudo procps tar findutils coreutils grep \
  libyuma-base
