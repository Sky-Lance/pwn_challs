GPNCTF24:
=======

<h3> Never-gonna-give-you-ub </h3>

> ret2win.

<h3> Gift </h3>

> Calls a read, set rax with length of payload (exact for execveat), and return to a xor rdx rdx, syscall gadget.

<h3> Petween-reasonable-lines </h3>

> Cheesed by calling syscall2plt, got leaks from rsp. (intended solution was to smuggle shellcode with jmps)

<h3> Dreamer </h3>

> Brute which value performs a ret, then modify return address to ret2win.
