#!/bin/bash -x

autoreconf -iv && ./configure --prefix=/opt/local && make clean && make -j 4 all && make check
#autoreconf -iv && ./configure --prefix=/opt/local && make clean && make -j 4 all && make check && sudo make install && sudo chown -R uri *

