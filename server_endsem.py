import socket
import hashlib
from typing import Tuple
import json
from elgamal.elgamal_config import *
from rsa.rsa_config import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

with open("key.pem", "rb") as f:
    rsa_private_key = RSA.import_key(f.read())

with open("public_key.pem", "rb") as f:
    rsa_public_key = RSA.import_key(f.read())

print("RSA Public Key: ", rsa_public_key)
print("RSA Private Key: ", rsa_private_key)


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

        print("Data Received", data)
        print("JSON LOADs")
        vote_data = json.loads(data)
        print(vote_data)


        elgamal_private_key = vote_data["elgamal_private_key"]
        elgamal_public_key = vote_data["elgamal_public_key"]
        votes = vote_data["votes"]

        final_tally = {
            'BA': 0,
            'BB': 0,
        }

        # Table heading print
        print("Name\t\tContestor\t\tVote Hash\t\tSignature\n")

        for lol in votes:

            c1 = lol["c1"]
            c2 = lol["c2"]
            signature_c1 = lol["signature_c1"]
            signature_c2 = lol["signature_c2"]
            signature_c1 = long_to_bytes(signature_c1)
            signature_c2 = long_to_bytes(signature_c2)

            ct = (c1, c2)
            c1 = c1.encode()
            c2 = c2.encode()

            verify_signature1 = rsa_verify(rsa_public_key, c1, signature_c1)
            verify_signature2 = rsa_verify(rsa_public_key, c2, signature_c2)
            c1 = int(c1.decode())
            c2 = int(c2.decode())

            ct = (c1, c2)

            sign_verified = verify_signature1 and verify_signature2

            pt = elgamal_decrypt(elgamal_private_key, elgamal_public_key, ct)


            # # print clean voter details
            # print("Voter Name: ", lol["name"])
            # print("Contestor: ", lol["contestor"])
            # print("Vote Hash:" , pt)            

            # print in table
            print(f"{lol['name']}\t\t| {lol['contestor']} \t\t| {pt} | {sign_verified}")

            if sign_verified:
                final_tally[lol["contestor"]] ^= pt


        print("\n\nFinal Tally")
        print("Contestor\t\tVotes")
        for key, value in final_tally.items():
            print(f"{key}\t\t{value}")

        json_tally = json.dumps(final_tally)
        print("JSON Tally: ", json_tally)
        long_tally = bytes_to_long(json_tally.encode())

        encryted_tally = elgamal_encrypt(elgamal_public_key, long_tally)
        print("Encrypted Tally: ", encryted_tally)

        decrytped_tally = elgamal_decrypt(elgamal_private_key, elgamal_public_key, encryted_tally)

        print("Decrypted Tally: ", decrytped_tally)

        # Send the hash back to the client
        send_data(client_socket, json_tally.encode())
    finally:
        client_socket.close()


def receive_data(client_socket: socket.socket, buffer_size: int = 8096) -> bytes:
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
