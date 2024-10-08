from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# AES Encryption
def aes_encrypt(key, plaintext, mode=AES.MODE_CBC):
    cipher = AES.new(key, mode)
    iv = cipher.iv  # Initialization vector (IV) for modes like CBC
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + ciphertext  # Return IV + ciphertext for decryption


# AES Decryption
def aes_decrypt(key, ciphertext, mode=AES.MODE_CBC):
    iv = ciphertext[: AES.block_size]
    ciphertext = ciphertext[AES.block_size :]
    cipher = AES.new(key, mode, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext


# DES Encryption
def des_encrypt(key, plaintext, mode=DES.MODE_CBC):
    cipher = DES.new(key, mode)
    iv = cipher.iv  # Initialization vector (IV) for modes like CBC
    ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))
    return iv + ciphertext  # Return IV + ciphertext for decryption


# DES Decryption
def des_decrypt(key, ciphertext, mode=DES.MODE_CBC):
    iv = ciphertext[: DES.block_size]
    ciphertext = ciphertext[DES.block_size :]
    cipher = DES.new(key, mode, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return plaintext


# Double DES Encryption
def double_des_encrypt(key1, key2, plaintext, mode=DES.MODE_CBC):
    cipher1 = DES.new(key1, mode)
    iv1 = cipher1.iv
    intermediate = cipher1.encrypt(pad(plaintext, DES.block_size))

    cipher2 = DES.new(key2, mode, iv=iv1)
    ciphertext = cipher2.encrypt(intermediate)
    return iv1 + ciphertext  # Return IV + ciphertext for decryption


# Double DES Decryption
def double_des_decrypt(key1, key2, ciphertext, mode=DES.MODE_CBC):
    iv1 = ciphertext[: DES.block_size]
    ciphertext = ciphertext[DES.block_size :]

    cipher2 = DES.new(key2, mode, iv=iv1)
    intermediate = cipher2.decrypt(ciphertext)

    cipher1 = DES.new(key1, mode, iv=iv1)
    plaintext = unpad(cipher1.decrypt(intermediate), DES.block_size)
    return plaintext


# Helper function to generate random keys
def generate_aes_key(size=32):  # Default is 256-bit key
    return get_random_bytes(size)


def generate_des_key():
    return get_random_bytes(8)  # 64-bit DES key


def generate_double_des_key():
    return get_random_bytes(8), get_random_bytes(8)  # Two 64-bit DES keys
