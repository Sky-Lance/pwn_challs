PwnMeCTF25
=======

<h3> Got </h3>

> Overwrite GOT function with win function.

<h3> Einstein </h3>

> Malloc big chunk to get one arb offsetted write into libc, use that to leak libc and stack by overwrite __IO_2_1_stdout_ write_base, then use address writes to overwrite ret addr with onegad and set one constraint.

<h3> Noprint </h3>

> Format string width specifier, overwrote stack address with itself, overwrite libc start main to onegad and printf's ret with a leave ret gadget (or something else in init, dont remember tbh).

<h3> Compress </h3>

> Leaks through partial overwrite -> Stack based heap pointer null byte overflow -> Faking unsorted bin chunk on stack -> profit (solved by tourpran & r0r1)
