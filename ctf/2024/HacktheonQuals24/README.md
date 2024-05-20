HacktheonQuals24
=======

<h3> Intelitigation </h3>

> Service had a way to get canary (?) and canary was an 8-byte value. Exploit using partial overwrite to get leak through strcpy and ret2main, and then pop rdi, write file name (flag\x00 in this case), and then ret2win, which reads the file to stdout.