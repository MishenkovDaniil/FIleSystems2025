#!/bin/bash


dd if=/dev/zero of=disk.img bs=1M count=2

mkfs.fat -F 16 disk.img
sudo mount -o loop disk.img /mnt
sudo umount /mnt