from pwn import *
from icecream import ic

elf = exe = ELF("./target")

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
        return remote("94.237.58.155", 46905)
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
def i(): return io.interactive()

io = start()

ru("dy? (y/n)")
sl(b'y')

rl()
while True:
    send = []
    data = rl().decode().strip().split()
    ic(data)
    for i in range(len(data)):
        if i == 0:
            if "PHREAK" in data[i]:
                send += "DROP"
            if "GORGE" in data[i]:
                send += "STOP"
            if "FIRE" in data[i]:
                send += "ROLL"
        else:
            if "PHREAK" in data[i]:
                send += "-DROP"
            if "GORGE" in data[i]:
                send += "-STOP"
            if "FIRE" in data[i]:
                send += "-ROLL"
        tosend = "".join(send)
    ru("What do you do?")
    sl(tosend.encode())


        

i()
