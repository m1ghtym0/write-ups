#!/usr/bin/env bash
qemu-system-aarch64 -m 1024 -cpu cortex-a57 -M virt -nographic \
    -pflash flash0.img -pflash flash1.img \
    -drive if=none,file=bionic-server-cloudimg-arm64.img,id=hd0 \
    -device virtio-blk-device,drive=hd0 \
    -net user,hostfwd=tcp:127.0.0.1:4242-:4242,hostfwd=tcp:127.0.0.1:1234-:1234,hostfwd=tcp:127.0.0.1:6022-:22 \
    -net nic \
