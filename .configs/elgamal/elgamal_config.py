from Crypto.PublicKey import ElGamal, RSA
from Crypto.Random import random
from Crypto.Hash import SHA256, SHA1, SHA512
from Crypto.Signature import pkcs1_15, DSS


# Generate ElGamal key pair
def generate_elgamal_key_pair(key_size=2048):
    key = ElGamal.generate(key_size, random.get_random_bytes)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key


# ElGamal Encryption
def elgamal_encrypt(public_key, plaintext):
    k = random.StrongRandom().randint(1, public_key.p - 2)
    ciphertext = public_key.encrypt(plaintext, k)
    return ciphertext


# ElGamal Decryption
def elgamal_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(ciphertext)
    return plaintext


# ElGamal Digital Signature Creation (using DSA)
def elgamal_sign(private_key, message):
    hash_obj = SHA256.new(message)
    signature = private_key.sign(
        hash_obj.digest(), random.StrongRandom().randint(1, private_key.q)
    )
    return signature


# ElGamal Digital Signature Verification (using DSA)
def elgamal_verify(public_key, message, signature):
    hash_obj = SHA256.new(message)
    try:
        return public_key.verify(hash_obj.digest(), signature)
    except (ValueError, TypeError):
        return False


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
    return private_key.export_key()


def export_public_key(public_key):
    return public_key.export_key()
