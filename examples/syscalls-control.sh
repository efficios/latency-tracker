#!/bin/bash

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
