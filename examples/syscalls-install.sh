#!/bin/bash

set -e

rm -rf tmp

mkdir tmp
pushd tmp

wget -O lttng-modules.tar.gz https://github.com/lttng/lttng-modules/archive/v2.6.0.tar.gz
wget -O libunwind.tar.gz https://github.com/fdoray/libunwind/archive/per_thread_cache.tar.gz
wget -O lttng-profile.tar.gz https://github.com/fdoray/lttng-profile/archive/latency_tracker.tar.gz

tar -xf lttng-modules.tar.gz
tar -xf libunwind.tar.gz
tar -xf lttng-profile.tar.gz

export CFLAGS='-O3'

# Install patched lttng-modules.
pushd lttng-modules-2.6.0
patch -p1 < ../../../extras/0001-connect-to-latency_tracker-tracepoints.patch
make -j4
sudo make modules_install
sudo depmod -a
popd

# Install libunwind.
pushd libunwind-per_thread_cache
./autogen.sh
./configure --enable-block-signals=false
make -j4
sudo make install
popd

# Install lttng-profile.
pushd lttng-profile-latency_tracker
./bootstrap
./configure
make -j4
sudo make install
sudo ldconfig
popd

popd

rm -rf tmp

# Install latency_tracker.
pushd ..
make -j4
sudo make modules_install
sudo depmod -a
popd

echo 'tracker and syscalls modules installed successfully.'
echo 'run "./syscalls-control.sh load" to load them'
