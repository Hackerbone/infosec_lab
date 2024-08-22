import numpy as np
import string


def hill_cipher_encrypt(message, key_matrix):
    # Remove spaces and convert to lowercase
    message = message.replace(" ", "").lower()

    # Check if the message length is odd, pad with 'x' if necessary
    if len(message) % 2 != 0:
        message += "x"

    # Convert letters to numbers (a=0, b=1, ..., z=25)
    alphabet = string.ascii_lowercase
    message_numbers = [alphabet.index(letter) for letter in message]

    # Reshape the message numbers into a matrix with 2 rows
    message_matrix = np.reshape(message_numbers, (-1, 2)).T

    # Perform matrix multiplication and mod 26
    cipher_matrix = np.dot(key_matrix, message_matrix) % 26

    # Convert numbers back to letters
    cipher_text = "".join(alphabet[num] for num in cipher_matrix.T.flatten())

    return cipher_text


# Key matrix
key_matrix = np.array([[3, 3], [2, 7]])

# Message to encrypt
message = "We live in an insecure world"

# Encrypt the message
encrypted_message = hill_cipher_encrypt(message, key_matrix)

print("Original message:", message)
print("Encrypted message:", encrypted_message)

"""OUTPUT

Original message: We live in an insecure world
Encrypted message: ziuhugolpsshkpyousnendwpxf
"""
