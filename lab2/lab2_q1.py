from Crypto.Cipher import DES
from binascii import unhexlify

# Key as a hexadecimal string
key_hex = "A1B2C3D4A1B2C3D4" # Note: repeated twice because key needs to be 8 bytes

# Convert the hexadecimal key to bytes
key = unhexlify(key_hex)

def encrypt(msg):
    cipher = DES.new(key, DES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag

def decrypt(nonce, ciphertext, tag):
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False

# Encrypt the message "Confidential Data"
nonce, ciphertext, tag = encrypt("Confidential Data")
print(f'Ciphertext: {ciphertext}')

# Decrypt the ciphertext to verify the original message
plaintext = decrypt(nonce, ciphertext, tag)
if not plaintext:
    print('Message is corrupted')
else:
    print(f'Plaintext: {plaintext}')
