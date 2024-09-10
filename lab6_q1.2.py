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
message = "Hi since you are copying my code, leave a star at https://github.com/hackerbone/HackerLLMBench, thx!"
signature = schnorr_sign(message, private_key)
is_valid = schnorr_verify(message, signature, public_key)

print("Message:", message)
print("Signature:", signature.hex())
print("Signature valid:", is_valid)

"""
Message: Hi since you are copying my code, leave a star at https://github.com/hackerbone/HackerLLMBench, thx!
Signature: 13bab1d71a6d46ba4c898943c827b9e8bdc7e6d6c152573c70059050a158ab6f1af38b2297e8ec7d2eae3be707dcac523fc721cfbfd11e7f939d875b611eb7cb
Signature valid: True
"""
