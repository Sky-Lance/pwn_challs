from pwn import *
from icecream import ic

elf = exe = ELF("./shogi")

context.binary = exe
# context.log_level = "debug"
context.aslr = True

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("localhost", 1337)
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

def makeMove(r, move):
    '''
    r    : pwntool remote instance (r = remote(IP, PORT))
    move : the move to play, see explanation below for details
    '''
    ### Some examples on how to construct moves to pass to the makeMove function
    #   1. To move a piece from <src_pos> to <dst_pos>, you are required to specify the two positions, for instance
    #      e.g. ((1,9),(1,8))
    #   2. When promoting is possible (and not mandatory) after moving, you must include the decision as the third entry of move tuple
    #      e.g. ((5,4),(5,3),'yes') / ((5,4),(5,3),'no')
    #   3. To drop a piece on the board, specify '打' (drop) + the piece to drop (e.g. '歩') along with the position to drop it
    #      e.g. ('打歩',(5,4))
    #   4. To surrender, send this as your move
    #      e.g. ('投了',)
    kanjimap = [c.encode() for c in ['','一','二','三','四','五','六','七','八','九']]
    if type(move[0])!=tuple:
        if len(move)==2:
            movstr = move[0].encode()+b' '+str(move[1][0]).encode()+b' '+kanjimap[move[1][1]]
        else:
            movstr = move[0].encode()
    else:
        movstr = b' '+str(move[0][0]).encode()+b' '+kanjimap[move[0][1]]+b'  '+str(move[1][0]).encode()+b' '+kanjimap[move[1][1]]
    r.sendlineafter(b'Player > ',movstr)
    if b'Promote' in r.recvline():
        r.sendline(move[2].encode())

io = start()

ru("Your Choice >")
sl(b'1')
ru("Your Choice >")
sl(b'2')

'''
makeMove(io, ((9, 7),(9, 6)))
makeMove(io, ((9, 6),(9, 5)))
makeMove(io, ((9, 5),(9, 4)))
makeMove(io, ((9, 4),(9, 3), "no"))
makeMove(io, ((9, 3),(9, 2), "no"))
makeMove(io, ((1, 9),(1, 8)))
makeMove(io, ((2, 8),(1, 8)))
makeMove(io, ((1, 8),(1, 2), "yes"))
makeMove(io, ((9, 9),(9, 8)))
makeMove(io, ((9, 8),(9, 1)))
makeMove(io, ((1, 2),(2, 2)))
makeMove(io, ((9, 1),(8, 1)))
makeMove(io, ((8, 1),(9, 1)))
makeMove(io, (('打角',(6, 2))))
makeMove(io, (('打金',(7, 1))))
makeMove(io, ((7, 1),(8, 1)))
makeMove(io, ((8, 1),(7, 1)))
makeMove(io, ((9, 1),(8, 1)))
makeMove(io, ((8, 1),(9, 1)))
makeMove(io, ((9, 1),(8, 1)))
makeMove(io, (('打金',(7, 1))))
makeMove(io, ((8, 1),(7, 1)))'''

makeMove(io, ((9, 7),(9, 6)))
makeMove(io, ((9, 6),(9, 5)))
makeMove(io, ((9, 5),(9, 4)))
makeMove(io, ((9, 4),(9, 3), "yes"))
makeMove(io, ((1, 9),(1, 7)))
makeMove(io, ((2, 9),(1, 7)))
makeMove(io, ((1, 7),(2, 5)))
makeMove(io, (('打歩',(1, 4))))
makeMove(io, ((1, 4),(1, 3), "yes"))
makeMove(io, ((8, 8),(9, 7)))
makeMove(io, ((2, 5),(1, 3), "yes"))
makeMove(io, ((9, 9),(9, 7)))
makeMove(io, (('打角',(1, 4))))
makeMove(io, ((1, 4),(2, 3), "yes"))
makeMove(io, ((8, 9),(9, 7)))
makeMove(io, ((9, 7),(8, 5)))
makeMove(io, (('打歩',(9, 4))))
makeMove(io, ((4, 9),(3, 8)))
makeMove(io, ((3, 8),(3, 7)))
makeMove(io, ((9, 4),(9, 3), "yes"))
makeMove(io, ((2, 3),(4, 1)))
makeMove(io, ((8, 7),(8, 6)))
makeMove(io, ((2, 8),(1, 8)))
makeMove(io, ((1, 8),(1, 3), "yes"))
makeMove(io, ((8, 5),(9, 3), "no"))
makeMove(io, ((9, 3),(8, 1)))
makeMove(io, ((8, 1),(7, 1)))
makeMove(io, ((7, 1),(6, 1)))
# makeMove(io, ((6, 1),(6, 2)))
# makeMove(io, ((7, 2),(7, 2)))
makeMove(io, ((7, 9),(8, 8)))
makeMove(io, ((1, 3),(1, 1)))
makeMove(io, ((8, 8),(9, 7)))
makeMove(io, ((8, 6),(8, 5)))
makeMove(io, ((8, 5),(8, 4)))
makeMove(io, (('打飛',(8, 5))))
makeMove(io, ((8, 4),(8, 3), "yes"))
makeMove(io, (('打銀',(2, 2))))
makeMove(io, ((2, 2),(1, 1), "yes"))
makeMove(io, ((1, 1),(2, 1)))
makeMove(io, ((6, 9),(7, 8)))
makeMove(io, ((7, 8),(8, 7)))
makeMove(io, ((8, 7),(9, 6)))
makeMove(io, ((2, 1),(3, 1)))
makeMove(io, ((3, 1),(4, 1)))
makeMove(io, ((9, 7),(9, 6)))
makeMove(io, ((4, 1),(5, 1)))
makeMove(io, ((9, 6),(9, 5)))
makeMove(io, ((9, 5),(9, 4)))
makeMove(io, (('打歩',(8, 4))))
makeMove(io, ((8, 4),(8, 3), "yes"))
makeMove(io, ((8, 3),(7, 2)))
makeMove(io, ((7, 2),(7, 1)))
makeMove(io, ((7, 1),(8, 1)))
makeMove(io, ((5, 9),(4, 9)))
makeMove(io, ((4, 9),(3, 9)))
makeMove(io, ((3, 9),(2, 9)))
makeMove(io, ((9, 4),(8, 3), "yes"))
makeMove(io, ((7, 7),(7, 6)))
makeMove(io, ((2, 9),(3, 9)))
makeMove(io, ((3, 9),(3, 8)))
makeMove(io, ((7, 6),(7, 5)))
makeMove(io, ((7, 5),(7, 4)))
makeMove(io, ((7, 4),(7, 3), "yes"))
makeMove(io, ((3, 8),(3, 7)))
makeMove(io, ((4, 7),(4, 6)))
makeMove(io, ((4, 6),(4, 5)))
makeMove(io, ((4, 5),(4, 4)))
makeMove(io, ((4, 4),(4, 3), "yes"))
makeMove(io, ((3, 7),(4, 7)))
makeMove(io, ((4, 7),(4, 8)))
makeMove(io, ((4, 8),(5, 8)))
makeMove(io, ((5, 8),(6, 8)))
makeMove(io, ((6, 8),(6, 7)))
makeMove(io, ((6, 7),(6, 8)))
makeMove(io, (('打歩',(6, 4))))
makeMove(io, ((6, 8),(5, 8)))
makeMove(io, ((6, 4),(6, 3), "yes"))
makeMove(io, ((5, 8),(4, 7)))
'''
makeMove(io, (('打銀',(3, 4))))
# makeMove(io, (('打銀',(3, 4))))
# makeMove(io, (('打銀',(2, 4))))
# makeMove(io, (('打銀',(1, 4))))
makeMove(io, ((4, 7),(5, 6)))
makeMove(io, (('打銀',(5, 4))))
makeMove(io, (('打銀',(2, 4))))
# makeMove(io, (('打銀',(6, 4))))
makeMove(io, (('打銀',(7, 1))))
makeMove(io, (('打銀',(5, 1))))
# makeMove(io, (('打銀',(5, 1))))
# makeMove(io, (('打銀',(4, 1))))
# makeMove(io, (('打銀',(3, 1))))
# makeMove(io, (('打銀',(2, 1))))
# makeMove(io, ((4, 6),(4, 5)))'''
makeMove(io, ('投了',))


i()
