TJCTF24
=======

<h3> All </h3>

> So many methods of exploitation, pick your choice. (I chose format string leak libc -> ret2libc)

<h3> Static </h3>

> Static binary, ret2syscall read binsh into bss and execve from there.

<h3> Numbersss </h3>

> Integer overflow -> ret2system.

<h3> Directory </h3>

> Partial overwrite to ret2win (but jump midway to avoid stack alignment).

<h3> Gargantuan </h3>

> Buffer overflow because strlen doesnt check past null byte, leak elf address off the stack with the help of strcpy and then ret2plt -> retlibc.

<h3> MIPSCode </h3>

> Shellcode in mips, level 1: orw on password file, level 2: execve shellcode without null bytes or whitespace.
