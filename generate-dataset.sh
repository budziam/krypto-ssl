#!/usr/bin/env bash

dd if=/dev/urandom of=./storage/datasets/dataset-512b bs=512 count=1
dd if=/dev/urandom of=./storage/datasets/dataset-512kB bs=512kB count=1
dd if=/dev/urandom of=./storage/datasets/dataset-4MB bs=4M count=1
dd if=/dev/urandom of=./storage/datasets/dataset-32MB bs=32M count=1
dd if=/dev/urandom of=./storage/datasets/dataset-64MB bs=32M count=2
dd if=/dev/urandom of=./storage/datasets/dataset-128MB bs=32M count=4
