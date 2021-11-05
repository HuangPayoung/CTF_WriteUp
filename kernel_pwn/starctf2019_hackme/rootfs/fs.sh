#!/bin/sh
find . | cpio -o --format=newc > ../initramfs.cpio

