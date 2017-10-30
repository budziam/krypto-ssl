#!/usr/bin/env bash

dd if=/dev/urandom of=./storage/dataset-512b bs=512 count=1
dd if=/dev/urandom of=./storage/dataset-512kB bs=512kB count=1
dd if=/dev/urandom of=./storage/dataset-4MB bs=4M count=1
dd if=/dev/urandom of=./storage/dataset-32MB bs=32M count=1
dd if=/dev/urandom of=./storage/dataset-64MB bs=64M count=2
dd if=/dev/urandom of=./storage/dataset-128MB bs=128M count=4
