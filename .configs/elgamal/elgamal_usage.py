import elgamal_config
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Generate ElGamal key pair
public_key, private_key = elgamal_config.elgamal_keygen()

# Example message
message = "Hello, ElGamal and SHA!"

# Encrypt and Decrypt
ciphertext = elgamal_config.elgamal_encrypt(public_key, bytes_to_long(message.encode()))
decrypted_int = elgamal_config.elgamal_decrypt(private_key, public_key, ciphertext)
decrypted_message = long_to_bytes(decrypted_int).decode()

# Sign and Verify
signature = elgamal_config.elgamal_sign(private_key, message, public_key)
is_valid = elgamal_config.elgamal_verify(public_key, message, signature)

# Export keys
exported_private_key = elgamal_config.export_private_key(private_key)
exported_public_key = elgamal_config.export_public_key(public_key)

# Hashing using SHA
sha256_hash_value = elgamal_config.sha256_hash(message.encode())
sha1_hash_value = elgamal_config.sha1_hash(message.encode())
sha512_hash_value = elgamal_config.sha512_hash(message.encode())

# Print outputs
print(f"Original Message: {message}")
print(f"Ciphertext: {ciphertext}")
print(f"Decrypted Message: {decrypted_message}")
print(f"Signature: {signature}")
print(f"Signature Valid: {is_valid}")
print(f"SHA-256: {sha256_hash_value}")
print(f"SHA-1: {sha1_hash_value}")
print(f"SHA-512: {sha512_hash_value}")
print(f"Exported Private Key: {exported_private_key}")
print(f"Exported Public Key: {exported_public_key}")

# # Demonstrate key import
# imported_private_key = elgamal_config.import_private_key(exported_private_key)
# imported_public_key = elgamal_config.import_public_key(exported_public_key)

# # Ensure imported keys work
# ciphertext_imported = elgamal_config.elgamal_encrypt(
#     imported_public_key, bytes_to_long(message.encode())
# )
# decrypted_int_imported = elgamal_config.elgamal_decrypt(
#     imported_private_key, imported_public_key, ciphertext_imported
# )
# decrypted_message_imported = long_to_bytes(decrypted_int_imported).decode()

# print(f"Decrypted Message with Imported Keys: {decrypted_message_imported}")
