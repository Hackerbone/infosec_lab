from ecdsa import SigningKey, NIST256p, BadSignatureError
import hashlib

# Generate Schnorr Keys
private_key = SigningKey.generate(curve=NIST256p)  # Private key
public_key = private_key.verifying_key  # Public key


# Schnorr Sign
def schnorr_sign(message, private_key):
    message_hash = hashlib.sha256(message.encode()).digest()
    signature = private_key.sign(message_hash, hashfunc=hashlib.sha256)
    return signature


# Schnorr Verify
def schnorr_verify(message, signature, public_key):
    try:
        message_hash = hashlib.sha256(message.encode()).digest()
        return public_key.verify(signature, message_hash, hashfunc=hashlib.sha256)
    except BadSignatureError:
        return False


# Example usage
message = "Hello, Schnorr!"
signature = schnorr_sign(message, private_key)
is_valid = schnorr_verify(message, signature, public_key)

print("Message:", message)
print("Signature:", signature.hex())
print("Signature valid:", is_valid)
