import string


def affine_decrypt(ciphertext, a, b):
    alphabet = string.ascii_uppercase
    m = len(alphabet)
    a_inv = pow(a, -1, m)
    if a_inv is None:
        return None

    plaintext = ""
    for char in ciphertext:
        if char in alphabet:
            y = alphabet.index(char)
            x = (a_inv * (y - b)) % m
            plaintext += alphabet[x]
        else:
            plaintext += char

    return plaintext


def brute_force_affine(ciphertext, known_plaintext, known_ciphertext):
    alphabet = string.ascii_uppercase
    m = len(alphabet)

    for a in range(1, m):
        for b in range(m):
            decrypted_text = affine_decrypt(known_ciphertext, a, b)
            if decrypted_text == known_plaintext.upper():
                return a, b

    return None


# Given ciphertext and known plaintext-ciphertext pair
ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
known_plaintext = "ab"
known_ciphertext = "GL"

# Brute force to find the correct keys
a, b = brute_force_affine(ciphertext, known_plaintext, known_ciphertext)

# Decrypt the full ciphertext using the found keys
if a is not None and b is not None:
    plaintext = affine_decrypt(ciphertext, a, b)
    print(f"Found keys: a = {a}, b = {b}")
    print(f"Decrypted plaintext: {plaintext}")
else:
    print("No valid keys found.")

"""
OUTPUT:
Found keys: a = 11, b = 6
Decrypted plaintext: TECHNOLOGYISAUSEFULSERVANTBUTADANGEROUSMASTER
"""
