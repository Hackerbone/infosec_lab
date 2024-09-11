from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from binascii import hexlify, unhexlify


# Function to generate RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return key, private_key, public_key


# Function to encrypt the message using RSA public key
def rsa_encrypt(plain_text, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    cipher_text = cipher.encrypt(plain_text.encode())
    return hexlify(cipher_text).decode()


# Function to decrypt the ciphertext using RSA private key
def rsa_decrypt(cipher_text, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_text = cipher.decrypt(unhexlify(cipher_text))
    return decrypted_text.decode()


# Generate RSA keys
key, private_key, public_key = generate_rsa_keys()

# Message to encrypt
plain_text = "Asymmetric Encryption"

# Encrypt the message using the public key
cipher_text = rsa_encrypt(plain_text, public_key)
print(f"Ciphertext: {cipher_text}")

# Decrypt the ciphertext using the private key
decrypted_text = rsa_decrypt(cipher_text, private_key)
print(f"Decrypted text: {decrypted_text}")

# Verify if the original message is recovered
assert decrypted_text == plain_text
