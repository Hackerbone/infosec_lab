import ecc_config

# Generate ECC key pair
private_key, public_key = ecc_config.generate_ecc_key_pair()

# Example message
message = b"Hello, ECC and SHA owowowowoow!"


ephemeral_pub_key, nonce, tag, ciphertext = ecc_config.ecc_encrypt(public_key, message)

print(f"Ephemeral Public Key: {ephemeral_pub_key}")
print(f"Nonce: {nonce}")
print(f"Tag: {tag}")
print(f"Ciphertext: {ciphertext}")

decrypted_message = ecc_config.ecc_decrypt(
    private_key, ephemeral_pub_key, nonce, tag, ciphertext
)

print(f"Decrypted Message: {decrypted_message}")

# Sign and Verify
signature = ecc_config.ecc_sign(private_key, ciphertext)
is_valid = ecc_config.ecc_verify(public_key, ciphertext, signature)

print("CIPHERTEXT")
print(f"Signature Valid: {is_valid}")
print(f"Message: {message}")

signature = ecc_config.ecc_sign(private_key, ciphertext)
is_valid = ecc_config.ecc_verify(public_key, ciphertext, signature)


print("PLAINTEXT")
print(f"Signature Valid: {is_valid}")
print(f"Message: {message}")

# Hashing using SHA
sha256_hash_value = ecc_config.sha256_hash(message)
sha1_hash_value = ecc_config.sha1_hash(message)
sha512_hash_value = ecc_config.sha512_hash(message)

# Print results
print(f"Message: {message}")
print(f"Signature Valid: {is_valid}")
print(f"SHA-256: {sha256_hash_value}")
print(f"SHA-1: {sha1_hash_value}")
print(f"SHA-512: {sha512_hash_value}")
