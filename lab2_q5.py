from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

# Key and message
key_hex = "FEDCBA9876543210FEDCBA9876543210"
key = binascii.unhexlify(key_hex)
message = "Top Secret Data"

# Encrypt the message
def aes_192_encrypt(msg, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_msg = pad(msg.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_msg)
    return ciphertext

# Decrypt the ciphertext
def aes_192_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size).decode('utf-8')
    return plaintext

# Perform encryption
ciphertext = aes_192_encrypt(message, key)
print(f'Ciphertext (hex): {ciphertext.hex()}')

# Perform decryption
plaintext = aes_192_decrypt(ciphertext, key)
print(f'Plaintext: {plaintext}')
