CyberSpaceCTF24
=======

<h3> ez-rop </h3>

> Stack-pivot -> use alarm() to set rax -> syscall (not solved)

<h3> menu </h3>

> leak libc -> rop to mprotect() -> write shellcode 8 bytes at a time -> shellcode: openat2, read, write (not solved)

<h3> shelltester </h3>

> Arm shellcoding

<h3> shelltester-v2 </h3>

> Arm32 rop (solved by heartstroller)

<h3> ticketbot-v1 </h3>

> Brute rand seed using a few sample vals (there's some cleaner way to do this) -> use seed to get libc leak -> ret2libc

<h3> ticketbot-v2 </h3>

> Change pass thru overflow -> get libc leak -> get canary leak thru login() -> ret2libc