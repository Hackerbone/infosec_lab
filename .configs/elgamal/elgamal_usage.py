import elgamal_config

# Generate ElGamal key pair
private_key, public_key = elgamal_config.generate_elgamal_key_pair()

# Example message
message = b"Hello, ElGamal and SHA!"

# Encrypt and Decrypt
ciphertext = elgamal_config.elgamal_encrypt(public_key, message)
plaintext = elgamal_config.elgamal_decrypt(private_key, ciphertext)

# Sign and Verify
signature = elgamal_config.elgamal_sign(private_key, message)
is_valid = elgamal_config.elgamal_verify(public_key, message, signature)

# Hashing using SHA
sha256_hash_value = elgamal_config.sha256_hash(message)
sha1_hash_value = elgamal_config.sha1_hash(message)
sha512_hash_value = elgamal_config.sha512_hash(message)

print(f"Message: {message}")
print(f"Ciphertext: {ciphertext}")
print(f"Decrypted: {plaintext}")
print(f"Signature Valid: {is_valid}")
print(f"SHA-256: {sha256_hash_value}")
print(f"SHA-1: {sha1_hash_value}")
print(f"SHA-512: {sha512_hash_value}")
