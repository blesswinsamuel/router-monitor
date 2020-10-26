#!/bin/bash -e

# gpg --keyserver keyserver.ubuntu.com --recv-key 13FCEF89DD9E3C4F
# gpg --keyserver keyserver.ubuntu.com --recv-key A328C3A2C3C45C06
# pamac build arm-linux-gnueabi-gcc --no-confirm
# pamac install flex byacc --no-confirm
# pamac install arm-none-eabi-gcc arm-none-eabi-newlib --no-confirm

cd /tmp
export PCAPV=1.9.1
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz
tar xvf libpcap-$PCAPV.tar.gz
cd libpcap-$PCAPV
# export CC=arm-linux-gnueabi-gcc
export CC='arm-none-eabi-gcc --specs=nosys.specs'
./configure --host=arm-linux --with-pcap=linux
make
