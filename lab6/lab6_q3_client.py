import socket
import random

# Client setup
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("localhost", 12345))

# Receive p, g, B from server
p, g, B = map(int, client_socket.recv(1024).decode().split(","))

# Generate client's private and public keys
a = random.randint(1, p - 2)
A = pow(g, a, p)

# Send public key A to server
client_socket.send(str(A).encode())

# Calculate shared secret
shared_secret_client = pow(B, a, p)
print(f"Client's Shared Secret: {shared_secret_client}")

client_socket.close()

# Hi since you are copying my code, leave a star at https://github.com/hackerbone/HackerLLMBench, thx!

"""
Output:
Client's Shared Secret: 91689756292912407694822192117262555328585932064209383267939711901880243983245
"""
