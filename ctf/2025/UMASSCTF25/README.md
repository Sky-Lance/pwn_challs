UMASSCTF25
=======

<h3> fact </h3>

> Given leak, ret2win.

<h3> riscy </h3>

> ret2shellcode in risc-v arch, given stack leak. (blooded)

<h3> calc </h3>

> Race condition leads index incrementation, which leads to oob reads, using that to get canary and libc leak, get stack leak by overwriting a pointer on the stack. (blooded) 

<h3> clue </h3>

> Given overflow, null byte into a stack pointer to get stack, libc leaks. Overwrite another pointer which gives us essentially an arb write primitive, overwrite free hook with onegad. 
