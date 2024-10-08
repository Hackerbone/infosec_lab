import ecc_config

# Generate ECC key pair
private_key, public_key = ecc_config.generate_ecc_key_pair()

# Example message
message = b"Hello, ECC and SHA!"

# Sign and Verify
signature = ecc_config.ecc_sign(private_key, message)
is_valid = ecc_config.ecc_verify(public_key, message, signature)

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
