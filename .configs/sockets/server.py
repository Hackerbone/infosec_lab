import socket
import hashlib
from typing import Tuple


def compute_hash(data: bytes) -> str:
    """
    Compute the SHA-256 hash of the given data.

    Args:
        data (bytes): The data to hash.

    Returns:
        str: The computed SHA-256 hash as a hexadecimal string.
    """
    return hashlib.sha256(data).hexdigest()


def handle_client_connection(client_socket: socket.socket) -> None:
    """
    Handle an incoming client connection by receiving data,
    computing its hash, and sending the hash back to the client.

    Args:
        client_socket (socket.socket): The socket connection to the client.
    """
    try:
        # Receive data from the client
        data = receive_data(client_socket)
        if not data:
            return

        # Compute hash of the received data
        received_hash = compute_hash(data)

        # Send the hash back to the client
        send_data(client_socket, received_hash.encode())
    finally:
        client_socket.close()


def receive_data(client_socket: socket.socket, buffer_size: int = 1024) -> bytes:
    """
    Receive data from the client socket.

    Args:
        client_socket (socket.socket): The socket connection to the client.
        buffer_size (int): The buffer size for receiving data.

    Returns:
        bytes: The data received from the client.
    """
    return client_socket.recv(buffer_size)


def send_data(client_socket: socket.socket, data: bytes) -> None:
    """
    Send data to the client socket.

    Args:
        client_socket (socket.socket): The socket connection to the client.
        data (bytes): The data to send to the client.
    """
    client_socket.send(data)


def start_server(host: str = "127.0.0.1", port: int = 65432) -> None:
    """
    Start the server, listen for incoming connections, and handle each client.

    Args:
        host (str): The server's hostname or IP address.
        port (int): The port to listen on.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")

    while True:
        client_socket, addr = accept_connection(server_socket)
        print(f"Accepted connection from {addr}")
        handle_client_connection(client_socket)


def accept_connection(
    server_socket: socket.socket,
) -> Tuple[socket.socket, Tuple[str, int]]:
    """
    Accept a new connection from a client.

    Args:
        server_socket (socket.socket): The server's listening socket.

    Returns:
        Tuple[socket.socket, Tuple[str, int]]: The client socket and address.
    """
    return server_socket.accept()


if __name__ == "__main__":
    start_server()
