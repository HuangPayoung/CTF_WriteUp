#!/bin/bash

#stty intr ^]
#cd `dirname $0`
# timeout --foreground 15 qemu-system-x86_64 \
qemu-system-x86_64 \
    -m 512M \
    -nographic \
    -kernel bzImage \
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 kaslr' \
    -monitor /dev/null \
    -initrd initramfs.cpio \
    -smp cores=2,threads=4 \
    -cpu qemu64,smep,smap 2>/dev/null \
    -s
