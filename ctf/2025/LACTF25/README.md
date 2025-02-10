LACTF25
=======

<h3> 2password </h3>

> Format string leak flag off stack.

<h3> state-change </h3>

> Stack pivot to overwrite variable and call win func.

<h3> minceraft </h3>

> Use gets to pivot into bss -> overwrite exit and alarm with ret -> use the readint function to control arg for puts to get leak -> profit (ret2system).

<h3> gamedev </h3>

> Heap overflow allows you to edit the address you can access by "exploring" from a different chunk. Exploring malloc got address for leak and overwriting with ret2system

<h3> library </h3>

> Array oob on allocating heap chunks allows you to have a type confusion with the book and settings struct, allowing you to read more than 0x10 bytes by editing the size of next chunk (which affects settings' size variable). Use this to read /proc/self/maps to get leaks and then House of Einheirjar -> FSOP

<h3> unsafe </h3>

> Array oob, after getting libc and stack leak, edit array base pointer to change the array to start at return address. And then you have some ocaml stuff (read my writeup :))

<h3> echo </h3>

> Kernel chall, with a patch that lets you read in 3 more bytes (not solved)

<h3> cloud-computing </h3>

> One of the functions (nucleate) had an integer overflow and allowed you to control the size of heap allocation, which you can also use to overwrite topchunk (not solved)

<h3> mmapro </h3>

> You can mmap anything once. mmapping the mmap function itself, with certain flags and a certain gadget, allows you to call gets to your shellcode. (not solved)

<h3> eepy </h3>

> Some weird shellcoding stuff? will look into it later. (not solved)

<h3> lamp </h3>

> Heap shenanigans. (not solved)


