from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256, SHA1, SHA512
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

# Generate ECC key pair
def generate_ecc_key_pair(curve="P-256"):
    private_key = ECC.generate(curve=curve)
    public_key = private_key.public_key()
    return private_key, public_key


# ECC Digital Signature Creation
def ecc_sign(private_key, message):
    hash_obj = SHA256.new(message)
    signer = DSS.new(private_key, "fips-186-3")
    signature = signer.sign(hash_obj)
    return signature


# ECC Digital Signature Verification
def ecc_verify(public_key, message, signature):
    hash_obj = SHA256.new(message)
    verifier = DSS.new(public_key, "fips-186-3")
    try:
        verifier.verify(hash_obj, signature)
        return True
    except ValueError:
        return False


# Hybrid Encryption using ECC and AES
def ecc_encrypt(public_key, plaintext):
    # Generate ephemeral ECC key pair
    ephemeral_key = ECC.generate(curve="P-256")

    # Derive shared secret from ephemeral private key and recipient's public key
    shared_secret = ephemeral_key.d * public_key.pointQ

    # Derive AES key from the shared secret
    shared_key = scrypt(
        str(shared_secret.x).encode(), salt=b"ecc_salt", key_len=32, N=2**14, r=8, p=1
    )

    # AES Encryption
    cipher_aes = AES.new(shared_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

    # Return the ephemeral public key along with ciphertext, nonce, and tag
    return ephemeral_key.public_key(), cipher_aes.nonce, tag, ciphertext


def ecc_decrypt(private_key, ephemeral_public_key, nonce, tag, ciphertext):
    # Derive shared secret from recipient's private key and ephemeral public key
    shared_secret = private_key.d * ephemeral_public_key.pointQ

    # Derive AES key from the shared secret
    shared_key = scrypt(
        str(shared_secret.x).encode(), salt=b"ecc_salt", key_len=32, N=2**14, r=8, p=1
    )

    # AES Decryption
    cipher_aes = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return plaintext


# SHA-256 Hashing
def sha256_hash(data):
    hash_obj = SHA256.new(data)
    return hash_obj.hexdigest()


# SHA-1 Hashing
def sha1_hash(data):
    hash_obj = SHA1.new(data)
    return hash_obj.hexdigest()


# SHA-512 Hashing
def sha512_hash(data):
    hash_obj = SHA512.new(data)
    return hash_obj.hexdigest()


# Helper function to export ECC keys
def export_private_key(private_key):
    return private_key.export_key(format="PEM")


def export_public_key(public_key):
    return public_key.export_key(format="PEM")
