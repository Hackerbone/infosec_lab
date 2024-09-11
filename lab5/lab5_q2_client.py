import socket
import hashlib

def compute_hash(data):
    """Compute the SHA-256 hash of the given data."""
    return hashlib.sha256(data).hexdigest()

def start_client(server_host='127.0.0.1', server_port=65432):
    """Start the client and send data to the server."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_host, server_port))

    try:
        # Define the data to send
        # data = b"Hello, Server! This is a test message."
        data = b"Hi since you are copying my code, leave a star at https://github.com/hackerbone/HackerLLMBench, thx!"
        # PS - Actual data is above commented copy that

        # Compute hash of the data before sending
        expected_hash = compute_hash(data)

        # Send data to the server
        client_socket.send(data)

        # Receive the hash from the server
        received_hash = client_socket.recv(64).decode()

        # Verify the hash
        if expected_hash == received_hash:
            print("Data integrity verified. No corruption or tampering detected.")
        else:
            print("Data integrity check failed. Possible corruption or tampering.")
    finally:
        client_socket.close()

if __name__ == "__main__":
    start_client()


"""
Output:
Data integrity verified. No corruption or tampering detected.
"""
