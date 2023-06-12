#!/bin/bash

echo {"0: "$1} | xxd -r | tee a.out >/dev/null
sleep 0.1
objdump -D -b binary -m aarch64