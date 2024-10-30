# Voting system

"""
Voter data:
name of voter
name of contestor
Vote


Eg:
Voter1, Contestor1, 1


The voter client hashes their vote binary 0 or 1 using SHA256 and sends it to the server.

hashed vote is encrypted using Elgamal encryption and sent to the server (Elgamal supports homomorphic encryption XOR)

The client signs the encrypted vote usingt their RSA private key, generating a digital signature

the client sends the encrypted vote and the digital signature to the server


Server Side:
1. Server receieves encrypted vote and signature
2. Signature verification using RSA
3. After verification use XOR to combine and calc final result (Homomorphic)
4. Send tally back to client
"""


import socket
import hashlib
import json
from elgamal.elgamal_config import *
from rsa.rsa_config import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

public_key, private_key = elgamal_keygen()

print("Elgamal Public Key: ", public_key)
print("Elgamal Private Key: ", private_key)

# # export and save rsa key in key.pem file
# with open("key.pem", "wb") as f:
#     f.write(rsa_private_key.export_key())

# with open("public_key.pem", "wb") as f:
#     f.write(rsa_public_key.export_key())

# import rsa key from key.pem file
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
        # Send data
        vote_info = {
            "name": "A",
            "contestor": "BA",
            "elgamal_private_key": private_key,
            "elgamal_public_key": public_key,
            "votes": [{
                "name": "A",
                "contestor": "BA",
                "vote": 1
            },
                {
                "name": "B",
                "contestor": "BA",
                "vote": 0
                },
                {
                "name": "C",
                "contestor": "BA",
                "vote": 1
                },
                {
                "name": "D",
                "contestor": "BB",
                "vote": 1
                }
            ]
        }

        for vote in vote_info["votes"]:
            vote_hash = compute_hash(str(vote["vote"]).encode())
            vote_hash = bytes_to_long(vote_hash.encode())
            enc_vote_hash = elgamal_encrypt(public_key, vote_hash)
            c1 = str(enc_vote_hash[0]).encode()
            c2 = str(enc_vote_hash[1]).encode()

            signature_c1 = rsa_sign(rsa_private_key, c1)
            signature_c2 = rsa_sign(rsa_private_key, c2)

            # how to send byte signature in json serializable way
            json_signature_c1 = bytes_to_long(signature_c1)
            json_signature_c2 = bytes_to_long(signature_c2)

            vote["signature_c1"] = json_signature_c1
            vote["signature_c2"] = json_signature_c2

            vote["c1"] = c1.decode()
            vote["c2"] = c2.decode()

        # vote_hash = compute_hash(b'1')
        # print("vote hash init", vote_hash)
        # vote_hash = bytes_to_long(vote_hash.encode())
        # enc_vote_hash = elgamal_encrypt(public_key, vote_hash)
        # print("vote hash long", vote_hash)
        # print("encrypted vote hash", enc_vote_hash)
    
        # c1 = str(enc_vote_hash[0]).encode()
        # c2 = str(enc_vote_hash[1]).encode()

        # signature_c1 = rsa_sign(rsa_private_key, c1)
        # signature_c2 = rsa_sign(rsa_private_key, c2)

        # # how to send byte signature in json serializable way
        # json_signature_c1 = bytes_to_long(signature_c1)
        # json_signature_c2 = bytes_to_long(signature_c2)

        # vote_info["signature_c1"] = json_signature_c1
        # vote_info["signature_c2"] = json_signature_c2

        # vote_info["c1"] = c1.decode()
        # vote_info["c2"] = c2.decode()

        print(vote_info)

        message = json.dumps(vote_info).encode("utf-8")

        print("message to be sent", message)

        # Send data to the server
        send_data(client_socket, message)

        # Receive the hash from the server
        tally = receive_data(client_socket)

        print("decrypted tally", tally)

    finally:
        client_socket.close()


if __name__ == "__main__":
    start_client()