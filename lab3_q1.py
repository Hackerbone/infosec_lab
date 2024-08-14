from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keys(bits=2048):
    # Generate RSA key pair
    key = RSA.generate(bits)
    
    # Extract public and private keys
    public_key = key.publickey()
    private_key = key
    
    # Export keys in PEM format for example
    public_key_pem = public_key.export_key().decode('utf-8')
    private_key_pem = private_key.export_key().decode('utf-8')
    
    # Extract n, e, d values
    n = key.n
    e = key.e
    d = key.d
    
    return public_key_pem, private_key_pem, n, e, d

def rsa_encrypt(message, n, e):
    # Create RSA key object from n and e
    key = RSA.construct((n, e))
    cipher = PKCS1_OAEP.new(key)
    
    # Encrypt the message
    ciphertext = cipher.encrypt(message.encode('utf-8'))
    return ciphertext

def rsa_decrypt(ciphertext, n, d):
    # Create RSA key object from n and d
    key = RSA.construct((n, 65537, d))  # 65537 is the common public exponent
    cipher = PKCS1_OAEP.new(key)
    
    # Decrypt the message
    decrypted_message = cipher.decrypt(ciphertext).decode('utf-8')
    return decrypted_message

# Generate RSA keys
public_key_pem, private_key_pem, n, e, d = generate_rsa_keys()

print("Public Key:")
print(public_key_pem)
print()
print("Private Key:")
print(private_key_pem)
print()
print("Modulus (n):", n)
print("Public Exponent (e):", e)
print("Private Exponent (d):", d)

# Example usage
message = "Asymmetric Encryption"
ciphertext = rsa_encrypt(message, n, e)
print(f"Ciphertext (bytes): {ciphertext}")

decrypted_message = rsa_decrypt(ciphertext, n, d)
print(f"Decrypted message: {decrypted_message}")
