from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify
import time

# Define the message
message = "Performance Testing of Encryption Algorithms"

# DES key (8 bytes / 16 hex characters)
des_key = b"12345678"

# AES-256 key (32 bytes / 64 hex characters)
aes_key_hex = "0123456789ABCDEF0123456789ABCDEF"
aes_key = unhexlify(aes_key_hex)

# Block size for AES and DES
aes_block_size = AES.block_size
des_block_size = DES.block_size

def measure_des_performance(msg):
    # DES encryption
    cipher = DES.new(des_key, DES.MODE_CBC)
    padded_msg = pad(msg.encode('utf-8'), des_block_size)
    start_time = time.perf_counter()
    ciphertext = cipher.encrypt(padded_msg)
    iv = cipher.iv
    encryption_time_s = time.perf_counter() - start_time
    encryption_time_ms = encryption_time_s * 1000  # Convert seconds to milliseconds

    # DES decryption
    cipher = DES.new(des_key, DES.MODE_CBC, iv=iv)
    start_time = time.perf_counter()
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, des_block_size).decode('utf-8')
    decryption_time_s = time.perf_counter() - start_time
    decryption_time_ms = decryption_time_s * 1000  # Convert seconds to milliseconds

    return encryption_time_ms, decryption_time_ms, plaintext

def measure_aes_performance(msg):
    # AES-256 encryption
    cipher = AES.new(aes_key, AES.MODE_CBC)
    padded_msg = pad(msg.encode('utf-8'), aes_block_size)
    start_time = time.perf_counter()
    ciphertext = cipher.encrypt(padded_msg)
    iv = cipher.iv
    encryption_time_s = time.perf_counter() - start_time
    encryption_time_ms = encryption_time_s * 1000  # Convert seconds to milliseconds

    # AES-256 decryption
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    start_time = time.perf_counter()
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, aes_block_size).decode('utf-8')
    decryption_time_s = time.perf_counter() - start_time
    decryption_time_ms = decryption_time_s * 1000  # Convert seconds to milliseconds

    return encryption_time_ms, decryption_time_ms, plaintext

# Measure DES performance
des_enc_time_ms, des_dec_time_ms, des_plaintext = measure_des_performance(message)
print(f"DES Encryption Time: {des_enc_time_ms:.6f} milliseconds")
print(f"DES Decryption Time: {des_dec_time_ms:.6f} milliseconds")
print(f"DES Plaintext: {des_plaintext}")

# Measure AES-256 performance
aes_enc_time_ms, aes_dec_time_ms, aes_plaintext = measure_aes_performance(message)
print(f"AES-256 Encryption Time: {aes_enc_time_ms:.6f} milliseconds")
print(f"AES-256 Decryption Time: {aes_dec_time_ms:.6f} milliseconds")
print(f"AES-256 Plaintext: {aes_plaintext}")
