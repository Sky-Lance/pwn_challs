VSCTF24:
=======

<h3> Sms2 </h3>

> Format string return address overwrite, except you need to ret2main every other instruction. (blooded :D)

<h3> VS-gateway </h3>

> Rust cmd injection.

<h3> Cosmic ray v3 </h3>

> Bit flipping challenge, this one had an unintended sol where you bit flip the ret to get infinite writes, and then write shellcode and execute.

<h3> Cosmic ray v3 - revenge </h3>

> Revenge challenge, flip the syscall so it calls read onto stack, ret2main get infinite flips. Then, flip the size bit to make bigger overflow. Finally, flip pop rbp to pop rdi, and simple ret2libc. (not solved)

<h3> Shell service </h3>

> Side-channel attack.

<h3> Domain Expansion </h3>

> T-cache poisoning, overwrite libc got. (not solved)
