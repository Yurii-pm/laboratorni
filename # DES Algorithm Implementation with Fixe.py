from typing import List

# Permutation function
def permute(block: List[int], table: List[int]) -> List[int]:
    return [block[x - 1] for x in table]

# XOR operation
def xor(bits1: List[int], bits2: List[int]) -> List[int]:
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

# DES key generation placeholder
def generate_keys(key: List[int]) -> List[List[int]]:
    # Placeholder for key schedule (16 subkeys)
    return [key for _ in range(16)]

# DES function (f-function placeholder)
def des_function(right: List[int], subkey: List[int]) -> List[int]:
    # Placeholder for f-function logic
    return xor(right, subkey[:len(right)])

# Initial Permutation (IP) table
IP_TABLE = [58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7]

# Final Permutation (IP-1) table
IP_INV_TABLE = [40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25]

# DES core function
def des(block: List[int], keys: List[List[int]], encrypt: bool = True) -> List[int]:
    block = permute(block, IP_TABLE)
    left, right = block[:32], block[32:]

    if not encrypt:
        keys = keys[::-1]  # Reverse keys for decryption

    for subkey in keys:
        temp_right = des_function(right, subkey)
        temp_right = xor(left, temp_right)
        left, right = right, temp_right

    combined = right + left  # Swap left and right
    return permute(combined, IP_INV_TABLE)

# Convert text to bit list
def text_to_bits(text: str) -> List[int]:
    bits = []
    for char in text:
        binval = bin(ord(char))[2:].zfill(8)
        bits.extend([int(bit) for bit in binval])
    return bits

# Convert bit list to text
def bits_to_text(bits: List[int]) -> str:
    chars = []
    for b in range(0, len(bits), 8):
        byte = bits[b:b + 8]
        chars.append(chr(int(''.join(map(str, byte)), 2)))
    return ''.join(chars)

# Encryption process
def encryption(plaintext: str) -> List[int]:
    assert len(plaintext) == 8, "Input must be exactly 8 ASCII characters."
    key = text_to_bits("DESCRYPT")  # Placeholder key
    keys = generate_keys(key)
    plaintext_bits = text_to_bits(plaintext)
    return des(plaintext_bits, keys, encrypt=True)

# Decryption process
def decryption(ciphertext: List[int]) -> str:
    key = text_to_bits("DESCRYPT")  # Placeholder key
    keys = generate_keys(key)
    decrypted_bits = des(ciphertext, keys, encrypt=False)
    return bits_to_text(decrypted_bits)

# User input and process
if __name__ == "__main__":
    # Input string from the user
    user_input = input("Enter a string (8 ASCII characters): ")

    # Validate input length
    if len(user_input) != 8:
        print("Error: Input must be exactly 8 ASCII characters.")
    else:
        # Encryption
        enc = encryption(user_input)
        print("Encrypted bits:", enc)

        # Decryption
        dec = decryption(enc)
        print("Decrypted text:", dec)
