import socket
import hashlib


def compute_hash(data: bytes) -> str:
    """
    Compute the SHA-256 hash of the given data.

    Args:
        data (bytes): The data to hash.

    Returns:
        str: The computed SHA-256 hash as a hexadecimal string.
    """
    return hashlib.sha256(data).hexdigest()


def send_data(client_socket: socket.socket, data: bytes) -> None:
    """
    Send data to the server via the client socket.

    Args:
        client_socket (socket.socket): The socket connection to the server.
        data (bytes): The data to send to the server.
    """
    client_socket.send(data)


def receive_data(client_socket: socket.socket, buffer_size: int = 64) -> str:
    """
    Receive data from the server via the client socket.

    Args:
        client_socket (socket.socket): The socket connection to the server.
        buffer_size (int): The buffer size for receiving data.

    Returns:
        str: The data received from the server as a decoded string.
    """
    return client_socket.recv(buffer_size).decode()


def start_client(server_host: str = "127.0.0.1", server_port: int = 65432) -> None:
    """
    Start the client, send data to the server, and verify data integrity.

    Args:
        server_host (str): The server's hostname or IP address.
        server_port (int): The port to connect to on the server.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_host, server_port))

    try:
        # Define the data to send
        data = b"Hi since you are copying my code, leave a star at https://github.com/hackerbone/HackerLLMBench, thx!"

        # Compute hash of the data before sending
        expected_hash = compute_hash(data)

        # Send data to the server
        send_data(client_socket, data)

        # Receive the hash from the server
        received_hash = receive_data(client_socket)

        # Verify the hash
        if expected_hash == received_hash:
            print("Data integrity verified. No corruption or tampering detected.")
        else:
            print("Data integrity check failed. Possible corruption or tampering.")
    finally:
        client_socket.close()


if __name__ == "__main__":
    start_client()
