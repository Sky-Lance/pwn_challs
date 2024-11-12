HackthevoteCTF24
=======

<h3> Inbound </h3>

> Negative indexing - got overwrite to win func.

<h3> catcpy </h3>

> use strcat and strcpy to first null out ret addr byte-by-byte, then write win func.

<h3> wall </h3>

> off by one allows rbp lsb overwrite - can pivot to ropchain and jump in the middle of main to call printf and scanf, then got overwrite (not solved in time, looked at authors sol)

<h3> Ideabook </h3>

> Heap overflow -> FSOP (not solved).
