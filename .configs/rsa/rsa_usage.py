import rsa_config

# Generate RSA key pair
private_key, public_key = rsa_config.generate_rsa_key_pair()

# Example message
message = b"Hello, Crypto!"

# Encrypt and Decrypt
ciphertext = rsa_config.rsa_encrypt(public_key, message)
plaintext = rsa_config.rsa_decrypt(private_key, ciphertext)

# Sign and Verify
signature = rsa_config.rsa_sign(private_key, message)
is_valid = rsa_config.rsa_verify(public_key, message, signature)

print(f"Message: {message}")
print(f"Ciphertext: {ciphertext}")
print(f"Decrypted: {plaintext}")
print(f"Signature Valid: {is_valid}")
