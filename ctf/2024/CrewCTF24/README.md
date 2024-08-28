CrewCTF24:
=======

<h3> Format-muscle </h3>

> Musl format string, cannot use offsets, due to musl optimizations, wrote a function to craft payload (apparently pwntools has a builtin function for this, screw me)

<h3> Pacipac </h3>

> Unintended, typecast error allows for negative indexing, can get leaks and overwrite return address of scanf, simple ret2libc.

<h3> Shellcode-game (x64) </h3>

> Wasn't in pwn, but still fun, so I added it (yes I got the source as well).


