final = (''' 
    mov ebx, esi
    add ebx, 101
''')

second = bytearray(b'H\xc7\xc7\x01\x00\x00\x00I\x81\xc6\xc0\x02\x00\x00L\x89\xf6H\xc7\xc2d\x00\x00\x00M1\xd2M1\xc0M1\xc9H\xc7\xc0,\x00\x00\x00\x0f\x05')

for i in range(len(second)):
    byte = second[i]
    if byte % 2 == 0:
        final += '\n    dec dword ptr [rbx]\n    inc ebx'
        second[i] += 1
    else:  # Odd
        final += '\n    inc ebx'

print("Modified Byte String:")
print(second)

print("\nAssembly Code:")
print(final)
