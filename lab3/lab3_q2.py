from Crypto.PublicKey import ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from binascii import hexlify, unhexlify

# Generate ECC keys
private_key = ECC.generate(curve="P-256")
public_key = private_key.public_key()

# Message to encrypt
plain_text = "Secure Transactions".encode()


# Encrypt the message using the ECC public key
def ecc_encrypt(plain_text, public_key):
    session_key = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(pad(plain_text, AES.block_size))
    enc_session_key = PKCS1_OAEP.new(public_key).encrypt(session_key)
    return hexlify(enc_session_key + cipher_aes.nonce + tag + ciphertext).decode()


# Decrypt the ciphertext using the ECC private key
def ecc_decrypt(ciphertext, private_key):
    data = unhexlify(ciphertext)
    enc_session_key, nonce, tag, ciphertext = (
        data[:32],
        data[32:48],
        data[48:64],
        data[64:],
    )
    session_key = PKCS1_OAEP.new(private_key).decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    return unpad(
        cipher_aes.decrypt_and_verify(ciphertext, tag), AES.block_size
    ).decode()


# Perform encryption
ciphertext = ecc_encrypt(plain_text, public_key)
print(f"Ciphertext: {ciphertext}")

# Perform decryption
decrypted_text = ecc_decrypt(ciphertext, private_key)
print(f"Decrypted text: {decrypted_text}")

# Verify the result
assert decrypted_text == plain_text.decode()
