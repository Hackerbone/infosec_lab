import symmetric_config

# AES Example
aes_key = symmetric_config.generate_aes_key()
aes_message = b"Hello, AES!"
aes_ciphertext = symmetric_config.aes_encrypt(aes_key, aes_message)
aes_plaintext = symmetric_config.aes_decrypt(aes_key, aes_ciphertext)

# DES Example
des_key = symmetric_config.generate_des_key()
des_message = b"Hello, DES!"
des_ciphertext = symmetric_config.des_encrypt(des_key, des_message)
des_plaintext = symmetric_config.des_decrypt(des_key, des_ciphertext)

# Double DES Example
double_des_key1, double_des_key2 = symmetric_config.generate_double_des_key()
double_des_message = b"Hello, Double DES!"
double_des_ciphertext = symmetric_config.double_des_encrypt(
    double_des_key1, double_des_key2, double_des_message
)
double_des_plaintext = symmetric_config.double_des_decrypt(
    double_des_key1, double_des_key2, double_des_ciphertext
)

# Print results
print(f"AES Ciphertext: {aes_ciphertext}")
print(f"AES Decrypted: {aes_plaintext}")

print(f"DES Ciphertext: {des_ciphertext}")
print(f"DES Decrypted: {des_plaintext}")

print(f"Double DES Ciphertext: {double_des_ciphertext}")
print(f"Double DES Decrypted: {double_des_plaintext}")
