#!/bin/sh
#
# Copyright (C) 2015 Julien Desfossez <jdesfossez@efficios.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; only
# version 2.1 of the License.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#

set -e

rm -rf tmp

mkdir tmp
cd tmp

wget -O lttng-modules.tar.gz https://github.com/lttng/lttng-modules/archive/v2.6.0.tar.gz
wget -O libunwind.tar.gz https://github.com/fdoray/libunwind/archive/per_thread_cache.tar.gz
wget -O lttng-profile.tar.gz https://github.com/fdoray/lttng-profile/archive/latency_tracker.tar.gz

tar -xf lttng-modules.tar.gz
tar -xf libunwind.tar.gz
tar -xf lttng-profile.tar.gz

export CFLAGS='-O3'

# Install patched lttng-modules.
cd lttng-modules-2.6.0
patch -p1 < ../../../extras/0001-connect-to-latency_tracker-tracepoints.patch
make -j4
sudo make modules_install
sudo depmod -a
cd ..

# Install libunwind.
cd libunwind-per_thread_cache
./autogen.sh
./configure --enable-block-signals=false
make -j4
sudo make install
cd ..

# Install lttng-profile.
cd lttng-profile-latency_tracker
./bootstrap
./configure
make -j4
sudo make install
sudo ldconfig
cd ..

cd ..

rm -rf tmp

# Install latency_tracker.
cd ..
make -j4
sudo make modules_install
sudo depmod -a
cd -

echo 'tracker and syscalls modules installed successfully.'
echo 'run "./syscalls-control.sh load" to load them'
