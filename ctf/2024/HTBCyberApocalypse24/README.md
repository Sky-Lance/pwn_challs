HTBCyberApocalypse24
=======

<h3> Tutorial </h3>

> Just a tutorial, asked about integers, signed integers and stuff.

<h3> Maze of Mist </h3>

> We have control over the first byte of the string we are comparing with, so we use null bytes to equate the strings. 

<h3> Delulu </h3>

> Using format string vulnerability to overwrite 2 bytes.

<h3> Rocket Blaster XXX </h3>

> Straight forward ROP.

<h3> Pet Companion </h3>

> Easy ret2plt to get leaks, then ret2libc.

<h3> Sound of Silence </h3>

> Spamming binsh and then calling system worked? Unintended?

<h3> Deathnote </h3>

> Heap, getting leaks from freed chunks and then calling a hidden function which executes our payload in the heap.

<h3> Oracle </h3>

> Using heap to get leaks -> orw on different sockets as the file is not run directly.

<h3> Maze of Mist </h3>

> Increasing stack size using command line arguments, so that we can use a kernel sigreturn syscall, which we use to call mprotect on the stack, and execute 32 bit orw shellcode. (Exploit doesn't work local for me.)
