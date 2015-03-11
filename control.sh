#!/bin/bash

if [ $# -lt 1 ]
then
        echo "Usage : $0 [load|unload|reload]"
        exit
fi

load_modules() {
  echo "loading latency_tracker"
  sudo killall lttng-sessiond
  sudo sudo lttng-sessiond -d --extra-kmod-probe=latency_tracker
  sudo modprobe tracker
  sudo modprobe syscalls
}

unload_modules() {
  echo "unloading latency_tracker"
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
