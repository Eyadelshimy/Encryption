# Initial Permutation (IP) and Final Permutation (FP) tables
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

# Expansion table (E)
E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23,
     24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

# Permutation table (P)
P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

# S-Boxes
S_BOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# Helper functions
def permute(bits, table):
    return ''.join(bits[i - 1] for i in table)

def xor(a, b):
    return ''.join(str(int(x) ^ int(y)) for x, y in zip(a, b))

def s_box_substitution(bits):
    output = ''
    for i in range(8):
        chunk = bits[i * 6:(i + 1) * 6]
        row = int(chunk[0] + chunk[-1], 2)
        col = int(chunk[1:5], 2)
        val = S_BOXES[i][row][col]
        output += format(val, '04b')
    return output

# DES Round
def des_round(L, R, K, round_num):
    print(f"\n--- Round {round_num} ---")
    print(f"L{round_num-1}: {L}")
    print(f"R{round_num-1}: {R}")

    # Expansion
    expanded_R = permute(R, E)
    print(f"Expanded R{round_num-1}: {expanded_R}")

    # Key Mixing
    xored = xor(expanded_R, K)
    print(f"XOR with Key: {xored}")

    # Substitution
    substituted = s_box_substitution(xored)
    print(f"After S-Box: {substituted}")

    # Permutation
    permuted = permute(substituted, P)
    print(f"After P-Box: {permuted}")

    # XOR with L
    new_R = xor(L, permuted)
    print(f"New R{round_num}: {new_R}")

    return R, new_R

# DES Encryption
def des_encrypt(plaintext, round_keys):
    print("\n--- Initial Permutation ---")
    plaintext = permute(plaintext, IP)
    print(f"After IP: {plaintext}")

    L, R = plaintext[:32], plaintext[32:]
    print(f"L0: {L}")
    print(f"R0: {R}")

    for i in range(16):
        L, R = des_round(L, R, round_keys[i], i + 1)

    # Swap and final permutation
    print("\n--- Final Swap and Permutation ---")
    combined = R + L
    print(f"After Swap: {combined}")
    ciphertext = permute(combined, FP)
    print(f"After FP: {ciphertext}")

    return ciphertext

# Example usage
if __name__ == "__main__":
    # Example plaintext (64 bits)
    plaintext = "0101010101010101010101010101010101010101010101010101010101010101"

    # Example Round Keys (16 identical keys for demonstration)
    round_keys = ["010101010101010101010101010101010101010101010101" for _ in range(16)]

    # Encrypt
    ciphertext = des_encrypt(plaintext, round_keys)
    print("\nFinal Ciphertext:", ciphertext)


    # Padding function (PKCS#7)
    def pad_plaintext(plaintext_bytes):
        pad_len = 8 - (len(plaintext_bytes) % 8)
        if pad_len == 0:
            pad_len = 8
        return plaintext_bytes + bytes([pad_len] * pad_len)


    # CBC Mode Encryption
    def des_cbc_encrypt(plaintext, round_keys, iv):
        # Convert plaintext to bytes and pad
        plaintext_bytes = plaintext.encode('utf-8')
        padded_bytes = pad_plaintext(plaintext_bytes)

        # Split into 8-byte blocks
        blocks = [padded_bytes[i:i + 8] for i in range(0, len(padded_bytes), 8)]

        # Convert each block to 64-bit binary string
        binary_blocks = [''.join(format(byte, '08b') for byte in block) for block in blocks]

        previous_cipher = iv
        ciphertext_blocks = []

        for i, block in enumerate(binary_blocks):
            print(f"\n--- Block {i + 1} ---")
            print(f"Plaintext Block: {block}")
            print(f"XOR with IV/Previous Ciphertext: {previous_cipher}")
            xored = xor(block, previous_cipher)
            print(f"XOR Result: {xored}")

            encrypted = des_encrypt(xored, round_keys)
            ciphertext_blocks.append(encrypted)
            previous_cipher = encrypted
            print(f"Ciphertext Block {i + 1}: {encrypted}")

        return ''.join(ciphertext_blocks)


    # Example usage
    if __name__ == "__main__":
        # Example Initialization Vector (64 zeros)
        IV = '0' * 64

        # Example Round Keys (16 identical keys for demonstration)
        round_keys = ["010101010101010101010101010101010101010101010101" for _ in range(16)]

        # Encrypting "Hello DES in CBC Mode"
        plaintext = "Hello DES in CBC Mode"
        ciphertext = des_cbc_encrypt(plaintext, round_keys, IV)
        print("\nFinal Ciphertext (binary):", ciphertext)