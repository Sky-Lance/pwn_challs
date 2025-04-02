#!/bin/sh
if [ -d /home/pwn ]; then
    cd /home/pwn
fi

exec qemu-system-x86_64 \
     -m 64M \
     -nographic \
     -kernel bzImage \
     -append "console=ttyS0 loglevel=3 oops=panic panic=-1 slab_nomerge nokaslr" \
     -no-reboot \
     -cpu qemu64 \
     -monitor /dev/null \
     -initrd rootfs.cpio \
     -net nic,model=virtio \
     -net user
