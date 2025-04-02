VolgaCTFQuals25
=======

<h3> Baby-welcome </h3>

> Byte by byte format string.

<h3> Sbsbx </h3>

> 3 part shellcode, allowed 9-10-9 bytes (need to use one for ret). First part: pushing flag.txt to stack, Second part: open("flag.txt"), Third part: sendfile.

<h3> Ponality </h3>

> Overlapping chunks, using overflow to get stack allocation and the shellcod after mprotect (solved by r0r1).

<h3> Ponsense </h3>

> Vm with relative oob, allocing a big chunk by giving huge number of instructions, using `sub` to get relative addresses, FSOP.