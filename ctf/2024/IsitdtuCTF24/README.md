IsitdtuCTF24
=======

<h3> Shellcode1 </h3>

> Cheesed with sendto() syscall.

<h3> Shellcode2 </h3>

> Self modifying shellcode, only odd bytes, sendto works once again.

<h3> No-name </h3>

> seed = 0 -> guess random number -> format string leaks and overwrite a value on stack -> arm ROP (almost solved)

<h3> Game-of-luck </h3>

> Brute until seed = 68 -> format string get leaks -> stack pivot -> execve("/bin/sh", 0, 0)