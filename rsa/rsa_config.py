from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# Generate RSA Key Pair
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key


# RSA Encryption
def rsa_encrypt(public_key, plaintext):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


# RSA Decryption
def rsa_decrypt(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


# RSA Digital Signature Creation
def rsa_sign(private_key, message):
    h = SHA256.new(message)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature


# RSA Digital Signature Verification
def rsa_verify(public_key, message, signature):
    h = SHA256.new(message)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# Helper functions to export keys
def export_private_key(private_key):
    return private_key.export_key()


def export_public_key(public_key):
    return public_key.export_key()
