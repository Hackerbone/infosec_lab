from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Util.number import GCD

# Key Generation
key = ElGamal.generate(256, get_random_bytes)
public_key = (int(key.p), int(key.g), int(key.y))  # Ensure all are integers
private_key = int(key.x)  # Ensure the private key is an integer


# Encryption
def elgamal_encrypt(message, key):
    p, g, y = int(key.p), int(key.g), int(key.y)  # Convert to native Python integers
    k = randint(1, p - 2)
    while GCD(k, p - 1) != 1:
        k = randint(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (message * pow(y, k, p)) % p
    return (c1, c2)


# Decryption
def elgamal_decrypt(cipher_text, key):
    c1, c2 = cipher_text
    p = int(key.p)  # Convert to native Python integer
    s = pow(c1, int(key.x), p)  # Convert to native Python integers
    # Use pow to compute the modular inverse
    s_inv = pow(s, p - 2, p)  # Fermat's Little Theorem
    return (c2 * s_inv) % p


# Example usage
message = 4441
cipher_text = elgamal_encrypt(message, key)
decrypted_message = elgamal_decrypt(cipher_text, key)

print("Original message:", message)
print("Encrypted message:", cipher_text)
print("Decrypted message:", decrypted_message)

"""
Output:
Original message: 4441
Encrypted message: (36885507269050816452521241110201113994024314479158945324704607565400925974332, 84005621770667733674079560558995776817276579165352124261201821962284727224889)
Decrypted message: 4441
"""
