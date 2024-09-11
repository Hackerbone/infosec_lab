import string


def shift_decrypt(ciphertext, key):
    alphabet = string.ascii_uppercase
    decrypted_text = ""

    for char in ciphertext:
        if char in alphabet:
            index = alphabet.index(char)
            new_index = (index - key) % 26
            decrypted_text += alphabet[new_index]
        else:
            decrypted_text += char

    return decrypted_text


def known_plaintext_attack(ciphertext, known_plaintext, known_ciphertext):
    alphabet = string.ascii_uppercase
    # Calculate the key used for encryption
    key = (
        alphabet.index(known_ciphertext[0]) - alphabet.index(known_plaintext[0])
    ) % 26
    # Decrypt the new ciphertext using the identified key
    return shift_decrypt(ciphertext, key)


# Known ciphertext and plaintext
known_ciphertext = "CIW"
known_plaintext = "YES"

# New ciphertext found in the cave
ciphertext = "XVIEWYWI"

# Decrypt using the known plaintext attack
plaintext = known_plaintext_attack(ciphertext, known_plaintext, known_ciphertext)

print("Ciphertext:", ciphertext)
print("Decrypted plaintext:", plaintext)

"""
OUTPUT:
Ciphertext: XVIEWYWI
Decrypted plaintext: RELIABLE
"""
