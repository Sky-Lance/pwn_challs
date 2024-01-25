from pwn import *

proc = input("Enter process name: ")
coff,crep = map(int,input("Enter cyclic length and rep size: ").split())

p = process(f'./{proc.strip()}')
elf = ELF(f'./{proc.strip()}')
p.sendline(cyclic(coff,n = crep))
p.wait()
core = p.corefile
fault = core.fault_addr
offset = cyclic_find(fault,n = crep)
print(f"OFFSET: {offset}")
