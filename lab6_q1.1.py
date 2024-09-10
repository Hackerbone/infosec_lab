from Crypto.PublicKey import ElGamal
from Crypto.Random import random
from Crypto.Util.number import GCD

# Key Generation
key = ElGamal.generate(256, random.get_random_bytes)
public_key = (key.p, key.g, key.y)
private_key = key.x


# Encryption
def elgamal_encrypt(message, key):
    k = random.StrongRandom().randint(1, key.p - 1)
    while GCD(k, key.p - 1) != 1:
        k = random.StrongRandom().randint(1, key.p - 1)
    c1 = pow(key.g, k, key.p)
    c2 = (message * pow(key.y, k, key.p)) % key.p
    return (c1, c2)


# Decryption
def elgamal_decrypt(cipher_text, key):
    c1, c2 = cipher_text
    s = pow(c1, key.x, key.p)
    s_inv = pow(s, -1, key.p)  # Modular inverse
    return (c2 * s_inv) % key.p


# Example usage
message = 12345
cipher_text = elgamal_encrypt(message, key)
decrypted_message = elgamal_decrypt(cipher_text, key)

print("Original message:", message)
print("Encrypted message:", cipher_text)
print("Decrypted message:", decrypted_message)
