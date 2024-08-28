def is_prime(n):
    """Check if a number is a prime number."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def find_non_primes(hex_string):
    """Convert hex string to decimal values and find non-prime numbers."""
    # Split the hex string into pairs of 2 characters
    hex_pairs = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    
    # Convert hex pairs to decimal values
    decimal_values = [int(pair, 16) for pair in hex_pairs]
    
    # Find and return non-prime numbers
    non_primes = [value for value in decimal_values if not is_prime(value)]
    return non_primes

# Example usage
hex_string = ("25020202020d020202023502020202352f02020235000202020d005302020d00650202350000020235000002033500006b033500000003350000006d89c789fb89da25020202020d020202023502020202353b02020235000202025383050700000005830502000000024389e58305110000000735000202023500020202830500000000030505")

non_primes = find_non_primes(hex_string)
print("Non-prime numbers:", non_primes)
