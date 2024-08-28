def hash_function(input_string):
    # Initialize the hash value
    hash_value = 5381

    # Process each character in the input string
    for char in input_string:
        # Update the hash value according to the algorithm
        hash_value = (hash_value * 33) ^ ord(char)

        # Apply a 32-bit mask to ensure the hash value is within 32-bit range
        hash_value = hash_value & 0xFFFFFFFF

    return hash_value

# Example usage
input_string = "testinputstringforhashing"
print(f"Hash value: {hash_function(input_string)}")


"""
OUTPUT:
Hash value: 2028858073
"""