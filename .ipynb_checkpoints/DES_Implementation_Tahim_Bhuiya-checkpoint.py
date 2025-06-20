# Tahim Bhuiya
# DES implementation in Python


from typing import List

# Globals for key and subkeys
key = 0
sub_keys = [0] * 16  # 48-bit integers

# Tables 
ip = [58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9,  1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7]      # initial permutation
ip_1 = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41,  9, 49, 17, 57, 25]    # final permutation
pc_1 = [57, 49, 41, 33, 25, 17, 9,
              1, 58, 50, 42, 34, 26, 18,
              10,  2, 59, 51, 43, 35, 27,
              19, 11,  3, 60, 52, 44, 36,
              63, 55, 47, 39, 31, 23, 15,
              7, 62, 54, 46, 38, 30, 22,
              14,  6, 61, 53, 45, 37, 29,
              21, 13,  5, 28, 20, 12,  4]    # permuted choice 1
pc_2 = [14, 17, 11, 24,  1,  5,
              3, 28, 15,  6, 21, 10,
              23, 19, 12,  4, 26,  8,
              16,  7, 27, 20, 13,  2,
              41, 52, 31, 37, 47, 55,
              30, 40, 51, 45, 33, 48,
              44, 49, 39, 56, 34, 53,
              46, 42, 50, 36, 29, 32]    # permuted choice 2
shift_bits = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]  # shift schedule
e = [32,  1,  2,  3,  4,  5,
           4,  5,  6,  7,  8,  9,
           8,  9, 10, 11, 12, 13,
          12, 13, 14, 15, 16, 17,
          16, 17, 18, 19, 20, 21,
          20, 21, 22, 23, 24, 25,
          24, 25, 26, 27, 28, 29,
          28, 29, 30, 31, 32,  1]       # expansion table
p = [16,  7, 20, 21,
           29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2,  8, 24, 14,
           32, 27,  3,  9,
           19, 13, 30,  6,
           22, 11,  4, 25 ]       # round permutation table
s_box = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
] 

# --- Utility Functions ---

def permute(bits: int, table: List[int], n: int) -> int:
    return sum(((bits >> (64 - table[i])) & 1) << (n - 1 - i) for i in range(n))

def left_shift28(k: int, shifts: int) -> int:
    return ((k << shifts) | (k >> (28 - shifts))) & ((1 << 28) - 1)

def generate_keys():
    global sub_keys
    permuted_key = permute(key, pc_1, 56)
    left = (permuted_key >> 28) & ((1 << 28) - 1)
    right = permuted_key & ((1 << 28) - 1)

    for round in range(16):
        left = left_shift28(left, shift_bits[round])
        right = left_shift28(right, shift_bits[round])
        combined = (left << 28) | right
        sub_keys[round] = permute(combined, pc_2, 48)

def expand(r: int) -> int:
    return permute(r, e, 48)

def substitute(bits: int) -> int:
    output = 0
    for i in range(8):
        six_bits = (bits >> (42 - 6 * i)) & 0x3F
        row = ((six_bits & 0x20) >> 4) | (six_bits & 1)
        col = (six_bits >> 1) & 0xF
        val = s_box[i][row][col]
        output = (output << 4) | val
    return output

def permute_p(bits: int) -> int:
    return permute(bits, p, 32)

def f(r: int, k: int) -> int:
    return permute_p(substitute(expand(r) ^ k))


def string_to_bits(s: str) -> int:
    return sum(ord(c) << (8 * (7 - i)) for i, c in enumerate(s))

def bits_to_string(bits: int) -> str:
    return ''.join(chr((bits >> (8 * (7 - i))) & 0xFF) for i in range(8))

def initial_permutation(bits: int) -> int:
    return permute(bits, ip, 64)

def final_permutation(bits: int) -> int:
    return permute(bits, ip_1, 64)


# --- DES Operations ---

def encrypt(plain: int) -> int:
    bits = initial_permutation(plain)
    left = (bits >> 32) & 0xFFFFFFFF
    right = bits & 0xFFFFFFFF

    for i in range(16):
        left, right = right, left ^ f(right, sub_keys[i])

    combined = (right << 32) | left  # note: final swap
    return final_permutation(combined)

def decrypt(cipher: int) -> int:
    bits = initial_permutation(cipher)
    left = (bits >> 32) & 0xFFFFFFFF
    right = bits & 0xFFFFFFFF

    for i in range(16):
        left, right = right, left ^ f(right, sub_keys[15 - i])

    combined = (right << 32) | left  # note: final swap
    return final_permutation(combined)

# --- Main Program ---

if __name__ == "__main__":
    plain_text = input("Enter the plaintext (8 characters): ")
    key_text = input("Enter the key (8 characters): ")

    if len(plain_text) != 8 or len(key_text) != 8:
        print("Error: Inputs must be exactly 8 characters (64 bits)")
        exit(1)

    plain_bits = string_to_bits(plain_text)
    key = string_to_bits(key_text)

    generate_keys()

    cipher = encrypt(plain_bits)
    print("Cipher Text (binary):", format(cipher, '064b'))

    decrypted_bits = decrypt(cipher)
    print("Decrypted Plain Text:", bits_to_string(decrypted_bits))

















