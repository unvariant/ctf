#!/bin/sh

gcc \
-o build/$1.bin \
-nostdlib -nostartfiles \
-fno-builtin -fno-stack-protector \
-ffreestanding -pie \
-Wl,--oformat=binary -Wl,-T,linker.ld \
-masm=intel \
-fomit-frame-pointer \
-pie -fPIE \
-O1 \
$1.c