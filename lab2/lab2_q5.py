from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii


def print_hex(data, label):
    print(f"{label}: {binascii.hexlify(data).decode()}")


# Convert the key and plaintext to bytes
key = binascii.unhexlify("FEDCBA9876543210FEDCBA9876543210")
plain_text = "Top Secret Data".encode()

# Pad the plaintext to make it a multiple of the block size (16 bytes)
padded_plaintext = pad(plain_text, AES.block_size)

# Initialize AES cipher in ECB mode (we will break down the steps manually)
cipher = AES.new(key, AES.MODE_ECB)

# Initial key addition (initial round)
initial_round_state = cipher.encrypt(padded_plaintext[:16])
print_hex(initial_round_state, "After Initial Round")

# Perform the encryption
ciphertext = cipher.encrypt(padded_plaintext)
print_hex(ciphertext, "Ciphertext")

# Decrypt the ciphertext
decrypted_text = unpad(cipher.decrypt(ciphertext), AES.block_size)
print_hex(decrypted_text, "Decrypted Text")

# Verify decryption matches the original plaintext
assert decrypted_text.decode() == "Top Secret Data"
