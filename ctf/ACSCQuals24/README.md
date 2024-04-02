LACTF24
=======

<h3> Rot13 </h3>

> Using negative indexing to get leaks, then ret2libc.

<h3> Fleeda </h3>

> Using read a read gadget to get libc leak, then memcpy to use 32 bit 'syscall' (int 0x80), which we use to call execve.

<h3> Shogi </h3>

> Found the bug, able to hold more than 19 pieces when that is the defined max, don't know how to exploit it. (Not Solved)