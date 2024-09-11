from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import binascii

# Key as a hexadecimal string (24 bytes / 48 hex characters)
key_hex = "1234567890ABCDEFAAFFFFFFFFFFFFFF1234567890ABCDEF"
key = binascii.unhexlify(key_hex)

# Define the message
message = "Classified Text"

def encrypt(msg):
    cipher = DES3.new(key, DES3.MODE_CBC)
    padded_msg = pad(msg.encode('utf-8'), DES3.block_size)
    ciphertext = cipher.encrypt(padded_msg)
    return cipher.iv, ciphertext

def decrypt(iv, ciphertext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    try:
        plaintext = unpad(padded_plaintext, DES3.block_size).decode('utf-8')
        return plaintext
    except ValueError:
        return False

# Encrypt the message
iv, ciphertext = encrypt(message)
print(f'Ciphertext (hex): {ciphertext.hex()}')

# Decrypt the ciphertext to verify the original message
plaintext = decrypt(iv, ciphertext)
if not plaintext:
    print('Message is corrupted')
else:
    print(f'Plaintext: {plaintext}')
