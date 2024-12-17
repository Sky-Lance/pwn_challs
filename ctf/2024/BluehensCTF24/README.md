BluehensCTF24
=======

<h3> Intro </h3>

> ret2win.

<h3> Write-what-where </h3>

> oob, can partial overwrite ret addr with win func (1/16 brute).

<h3> the-tv </h3>

> password is a pointer which cant be entered, fmtstr overwrite password with a value we know

<h3> ret2bf </h3>

> oob, `>`*64 gives ret addr, use it for leaks and write.

<h3> the-light </h3>

> oob, then use functions which increment byte ptr by small amounts - and SROP gadget given.

<h3> Flaming-lips </h3>

> t-cache poisoning with size manipulation to get libc leak - FSOP (not solved)
