UMDCTF25 (didn't play much due to travelling)
=======

<h3> gambling2 </h3>

> Oob in array, saved as floating point val, overwrite ret addr with win.

<h3> aura </h3>

> File struct overwrite by changing buf base and buf end to variable, and fileno to stdin, so it writes stdin input into variable.

<h3> unfinished </h3>

> Give big number + overwrite random pointer to trigger win function. (not solved)

<h3> prison-realm </h3>

> Interesting rop, unintended dlresolve. (not solved)

<h3> one-write </h3>

> Tcache poisoning with overlapping chunks to get leaks, and some smallbin tcache stashing shenanigans. (also you could apparently solve it with tcache poisoning?) (not solved) 

<h3> finished </h3>

> Faking an exception handler to call the win function. (not solved)

<h3> off-by-one-error </h3>

> Dunno, no writeups. (not solved)

<h3> literally-1984/1985 </h3>

> 1984 unintended - builtins. Bug was that turbofan optimized 2+2 to 5 so you could have an index oob. (not solved)
