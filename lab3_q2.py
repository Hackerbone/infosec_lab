from Crypto.PublicKey import ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

def generate_ecc_keys():
    # Generate ECC key pair
    key = ECC.generate(curve='P-256')
    
    # Export public and private keys in PEM format
    public_key_pem = key.public_key().export_key(format='PEM').decode('utf-8')
    private_key_pem = key.export_key(format='PEM').decode('utf-8')
    
    # Extract private and public key components
    private_key = key
    public_key = key.public_key()
    
    return public_key_pem, private_key_pem, private_key, public_key

def ecc_encrypt(message, public_key):
    # Generate a random session key for AES
    session_key = get_random_bytes(16)
    
    # Encrypt the message with AES
    cipher_aes = AES.new(session_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(pad(message.encode('utf-8'), AES.block_size))
    
    # Derive the encryption key using the public ECC key
    shared_secret = public_key.pointQ.x.to_bytes(32, 'big') + public_key.pointQ.y.to_bytes(32, 'big')
    encryption_key = SHA256.new(shared_secret).digest()
    
    # Encrypt the AES session key using the public ECC key
    cipher_ecc = PKCS1_OAEP.new(public_key)
    encrypted_session_key = cipher_ecc.encrypt(session_key)
    
    return encrypted_session_key, cipher_aes.iv + ciphertext

def ecc_decrypt(encrypted_session_key, ciphertext, private_key):
    # Derive the shared secret from the private key and the encrypted session key
    shared_secret = private_key.d.to_bytes(32, 'big') + private_key.pointQ.y.to_bytes(32, 'big')
    encryption_key = SHA256.new(shared_secret).digest()
    
    # Decrypt the AES session key using the private ECC key
    cipher_ecc = PKCS1_OAEP.new(private_key)
    session_key = cipher_ecc.decrypt(encrypted_session_key)
    
    # Decrypt the message with AES
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv=ciphertext[:16])
    decrypted_message = unpad(cipher_aes.decrypt(ciphertext[16:]), AES.block_size).decode('utf-8')
    
    return decrypted_message

# Generate ECC keys
public_key_pem, private_key_pem, private_key, public_key = generate_ecc_keys()

print("Public Key:")
print(public_key_pem)
print()
print("Private Key:")
print(private_key_pem)

# Example usage
message = "Secure Transactions"
encrypted_session_key, ciphertext = ecc_encrypt(message, public_key)
print(f"Ciphertext (bytes): {ciphertext}")

decrypted_message = ecc_decrypt(encrypted_session_key, ciphertext, private_key)
print(f"Decrypted message: {decrypted_message}")
