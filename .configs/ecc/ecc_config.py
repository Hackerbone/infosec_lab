from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256, SHA1, SHA512
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


# Generate ECC key pair
def generate_ecc_key_pair(curve="P-256"):
    private_key = ECC.generate(curve=curve)
    public_key = private_key.public_key()
    return private_key, public_key


# ECC Digital Signature Creation
def ecc_sign(private_key, message):
    hash_obj = SHA256.new(
        message
    )  # You can switch between SHA1, SHA256, or SHA512 based on needs
    signer = DSS.new(private_key, "fips-186-3")
    signature = signer.sign(hash_obj)
    return signature


# ECC Digital Signature Verification
def ecc_verify(public_key, message, signature):
    hash_obj = SHA256.new(
        message
    )  # You can switch between SHA1, SHA256, or SHA512 based on needs
    verifier = DSS.new(public_key, "fips-186-3")
    try:
        verifier.verify(hash_obj, signature)
        return True
    except ValueError:
        return False


# ECC Encryption is not standard in ECC (used for digital signatures mainly)
# However, you can use hybrid encryption with ECC for encrypting session keys
def ecc_encrypt(public_key, plaintext):
    session_key = get_random_bytes(32)  # AES session key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(session_key)
    return ciphertext


# ECC Decryption with hybrid encryption
def ecc_decrypt(private_key, ciphertext):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    plaintext = cipher_rsa.decrypt(ciphertext)
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
