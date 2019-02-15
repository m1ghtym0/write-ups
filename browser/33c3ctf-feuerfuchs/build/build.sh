#!/bin/bash

cd build
wget https://ftp.mozilla.org/pub/firefox/releases/50.1.0/source/firefox-50.1.0.source.tar.xz
tar xvf firefox-50.1.0.source.tar.xz
cd firefox-50.1.0.source
cp ../mozconfig .mozconfig
patch -p1 < ../feuerfuchs.patch
patch -p1 < ../icu.patch
patch -p1 < ../debug.patch
./mach build -j 6
