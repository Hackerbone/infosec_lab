from Crypto.Util.number import getPrime, inverse, bytes_to_long
from Crypto.Hash import SHA256, SHA1, SHA512
import random
from hashlib import sha256
from math import gcd


# ElGamal Key Generation
def elgamal_keygen(bits=256):
    p = getPrime(bits)  # Generate a large prime number p
    g = random.randint(2, p - 2)  # Random generator g (2 <= g <= p-2)
    x = random.randint(1, p - 2)  # Private key x (1 <= x <= p-2)
    h = pow(g, x, p)  # h = g^x mod p
    public_key = (p, g, h)
    private_key = x
    return public_key, private_key


# ElGamal Encryption
def elgamal_encrypt(public_key, message):
    p, g, h = public_key
    y = random.randint(1, p - 2)  # Random number y (1 <= y <= p-2)
    c1 = pow(g, y, p)  # c1 = g^y mod p
    s = pow(h, y, p)  # s = h^y mod p
    c2 = (message * s) % p  # c2 = m * s mod p
    return (c1, c2)


# ElGamal Decryption
def elgamal_decrypt(private_key, public_key, ciphertext):
    p, g, h = public_key
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)  # s = c1^x mod p
    s_inv = inverse(s, p)  # Modular inverse of s mod p
    m = (c2 * s_inv) % p  # m = c2 * s_inv mod p
    return m


# ElGamal Digital Signature Generation
def elgamal_sign(private_key, message, public_key):
    p, g, _ = public_key
    k = random.randint(1, p - 2)

    # Ensure that k is coprime with p - 1
    while gcd(k, p - 1) != 1:  # Check if gcd(k, p - 1) is 1
        k = random.randint(1, p - 2)

    r = pow(g, k, p)  # r = g^k mod p
    m = bytes_to_long(sha256(message.encode()).digest())
    s = (inverse(k, p - 1) * (m - private_key * r)) % (p - 1)
    return (r, s)


# ElGamal Digital Signature Verification
def elgamal_verify(public_key, message, signature):
    p, g, h = public_key
    r, s = signature
    if not (1 < r < p):
        return False

    m = bytes_to_long(sha256(message.encode()).digest())
    v1 = (pow(h, r, p) * pow(r, s, p)) % p
    v2 = pow(g, m, p)
    return v1 == v2


# SHA-256 Hashing
def sha256_hash(data):
    hash_obj = SHA256.new(data)
    return hash_obj.hexdigest()


# SHA-1 Hashing
def sha1_hash(data):
    hash_obj = SHA1.new(data)
    return hash_obj.hexdigest()


# SHA-512 Hashing
def sha512_hash(data):
    hash_obj = SHA512.new(data)
    return hash_obj.hexdigest()


# Helper functions to export keys
def export_private_key(private_key):
    # implement this function
    pass


def export_public_key(public_key):
    # implement this function
    pass
