PlaidCTF25
=======

<h3> tumbleweed </h3>

> Multiple allocators alloc and free, but easier to just use resize(0) to free and get a uaf.

<h3> ocalc </h3>

> From their discord: UAF on mpz structs -> underlying _mp_d is freed -> run enough gc cycles some _mp_d pointer will overlap other mpz structs -> overwrite and obtain arb r/w with other mpz struct _mp_d. (not solved)

<h3> bounty-board </h3>

> Overflow to top chunk and decrease size, free top chunk (similar to house of tangerine) to get libc address, partial overwrite said libc address to stdout, use negative memcpy to move into perthread struct, partial fsop for leaks, and then similar thing again for fsop for rce. (not solved)
