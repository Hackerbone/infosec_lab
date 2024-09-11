from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify

# Key as a hexadecimal string (16 bytes / 32 hex characters)
key_hex = "0123456789ABCDEF0123456789ABCDEF"

# Convert the hexadecimal key to bytes
key = unhexlify(key_hex)

# Define the AES block size
block_size = AES.block_size

def encrypt(msg):
    cipher = AES.new(key, AES.MODE_CBC)
    # Pad the message to be a multiple of the block size
    padded_msg = pad(msg.encode('utf-8'), block_size)
    ciphertext = cipher.encrypt(padded_msg)
    return cipher.iv, ciphertext

def decrypt(iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    try:
        # Unpad the plaintext and decode it
        plaintext = unpad(padded_plaintext, block_size).decode('utf-8')
        return plaintext
    except ValueError:
        return False

# Encrypt the message "Sensitive Information"
iv, ciphertext = encrypt("Sensitive Information")
print(f'Ciphertext (hex): {ciphertext.hex()}')

# Decrypt the ciphertext to verify the original message
plaintext = decrypt(iv, ciphertext)
if not plaintext:
    print('Message is corrupted')
else:
    print(f'Plaintext: {plaintext}')
