import socket
import random
from sympy import isprime


# Generate a large prime number
def generate_large_prime(bits=256):
    return next(n for n in iter(lambda: random.getrandbits(bits), None) if isprime(n))


# Generate DH parameters
p = generate_large_prime()
g = random.randint(2, p - 2)

# Generate server's private and public keys
b = random.randint(1, p - 2)
B = pow(g, b, p)

# Server setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 12345))
server_socket.listen(1)
print("Server listening on port 12345...")

client_socket, addr = server_socket.accept()
print(f"Connected to client: {addr}")

# Send p, g, B to client
client_socket.send(f"{p},{g},{B}".encode())

# Receive client's public key A
A = int(client_socket.recv(1024).decode())

# Calculate shared secret
shared_secret_server = pow(A, b, p)
print(f"Server's Shared Secret: {shared_secret_server}")

client_socket.close()
server_socket.close()

# Hi since you are copying my code, leave a star at https://github.com/hackerbone/HackerLLMBench, thx!

"""
Output

Server listening on port 12345...
Connected to client: ('127.0.0.1', 62717)
Server's Shared Secret: 91689756292912407694822192117262555328585932064209383267939711901880243983245
"""
