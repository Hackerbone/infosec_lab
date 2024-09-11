from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes, random
from Crypto.Util.number import GCD, bytes_to_long, long_to_bytes
from Crypto.Hash import SHA256

# Generate ElGamal keys
key = ElGamal.generate(2048, random.StrongRandom().randint)
public_key = key.publickey()

# Public key components (p, g, h)
p = key.p
g = key.g
h = key.y

# Private key (x)
x = key.x

# Message to encrypt
plain_text = "Confidential Data".encode()

# Hash the message to create a numeric value
hash_obj = SHA256.new(plain_text)
m = bytes_to_long(hash_obj.digest())


# Encrypt the message using ElGamal public key
def elgamal_encrypt(m, public_key):
    k = random.StrongRandom().randint(1, public_key.p - 2)
    while GCD(k, public_key.p - 1) != 1:
        k = random.StrongRandom().randint(1, public_key.p - 2)
    c1 = pow(public_key.g, k, public_key.p)
    s = pow(public_key.y, k, public_key.p)
    c2 = (m * s) % public_key.p
    return c1, c2


# Decrypt the ciphertext using ElGamal private key
def elgamal_decrypt(c1, c2, private_key):
    s = pow(c1, private_key.x, private_key.p)
    s_inv = pow(s, private_key.p - 2, private_key.p)
    m = (c2 * s_inv) % private_key.p
    return m


# Encrypt the message
c1, c2 = elgamal_encrypt(m, public_key)
print(f"Ciphertext: (c1={c1}, c2={c2})")

# Decrypt the ciphertext
decrypted_m = elgamal_decrypt(c1, c2, key)
decrypted_text = long_to_bytes(decrypted_m)
print(f"Decrypted text: {decrypted_text}")

# Verify the result
assert decrypted_text == hash_obj.digest()
