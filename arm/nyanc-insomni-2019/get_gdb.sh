#!/bin/bash

mkdir gdbtoolchain
cd gdbtoolchain
wget https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/aarch64-linux-gnu/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu.tar.xz
tar xvf gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu.tar.xz
cd ..
ln -s gdbtoolchain/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu/bin/./aarch64-linux-gnu-gdb gdb

