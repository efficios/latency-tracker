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

if [ $# -lt 1 ]
then
        echo "Usage : $0 [load|unload|reload]"
        exit
fi

load_modules() {
  echo "loading long syscalls tracker"
  sudo killall lttng-sessiond 2> /dev/null
  sudo sudo lttng-sessiond -d --extra-kmod-probe=latency_tracker
  sudo modprobe tracker
  sudo modprobe syscalls
  echo "syscalls tracker loaded successfully"
}

unload_modules() {
  echo "unloading long syscalls tracker"
  sudo rmmod syscalls
  sudo rmmod tracker
}

reload_modules() {
  unload_modules
  load_modules
}

case "$1" in
load)
  load_modules
    ;;
unload)
  unload_modules
    ;;
reload)
  reload_modules
    ;;
*) echo "unkown command $1"
   ;;
esac
