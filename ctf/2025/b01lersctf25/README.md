b01lersCTF25
=======

<h3> where </h3>

> Given stack leak, ret2shellcode.

<h3> gadget-freak </h3>

> Given an rwx section with a bunch of gadgets, use xchg gadgets to set up registers for execve.

<h3> gueswhosstack </h3>

> One format string for leak, 2 writes. Partial relro allows for overwriting got. Found a gadget that allows to set a register and second write for onegadget. 

<h3> trolley-problem </h3>

> Canary brute -> partial overwrite ret2win.

<h3> scanner </h3>

> Scanf bug, similar to printf, allows for format string writes only. Given leak of stdout, 1/16 brute address on stack to stdout, partial overwrite stdout for libc/stack leak, and do fsop/retaddr overwrite. (unintended, intended uses %ms to mmap a chunk)

<h3> lose-cash </h3>

> Null byte overflow allows you to set randstate type to 0, which uses LCG, which is (kinda) reversible, using that to get heap leak, and a lot of other dings. (not solved)