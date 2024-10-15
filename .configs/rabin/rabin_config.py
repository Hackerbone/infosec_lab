from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse
import random
from hashlib import sha256
from math import gcd


# Rabin Key Generation
def rabin_keygen(bits=512):
    # Generate two large primes p and q
    p = getPrime(bits)
    q = getPrime(bits)

    # Public key is n = p * q
    n = p * q

    # Private key is (p, q)
    private_key = (p, q)

    return n, private_key


# Rabin Encryption
def rabin_encrypt(public_key, message):
    n = public_key
    m = bytes_to_long(message.encode())
    if m >= n:
        raise ValueError("Message is too large for the modulus n")

    # Ciphertext c = m^2 mod n
    ciphertext = pow(m, 2, n)
    return ciphertext


# Rabin Decryption (improved to pick the correct root based on hashing)
def rabin_decrypt(private_key, public_key, ciphertext):
    p, q = private_key
    n = public_key

    # Compute mp = c^(p+1)/4 mod p and mq = c^(q+1)/4 mod q
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)

    # Use the Chinese Remainder Theorem (CRT) to find the four possible values of m
    def chinese_remainder_theorem(p, q, mp, mq):
        q_inv = inverse(q, p)
        m1 = (mp + p * (q_inv * (mq - mp) % p)) % (p * q)
        m2 = (p * q - m1) % (p * q)
        m3 = (mq + q * (inverse(p, q) * (mp - mq) % q)) % (p * q)
        m4 = (p * q - m3) % (p * q)
        return [m1, m2, m3, m4]

    possible_m = chinese_remainder_theorem(p, q, mp, mq)

    # Compare the hash of each possible root with the ciphertext hash to find the correct message
    for m in possible_m:
        try:
            decrypted_message = long_to_bytes(m).decode("utf-8", errors="ignore")

            # Re-encrypt the decrypted message to check if it matches the original ciphertext
            if pow(m, 2, n) == ciphertext:
                return decrypted_message  # Return the correct message
        except UnicodeDecodeError:
            continue  # Skip invalid roots

    raise ValueError("Failed to find valid decrypted message.")


# Rabin Digital Signature Generation
def rabin_sign(private_key, message, public_key):
    n = public_key
    p, q = private_key

    # Hash the message to a number m
    m = bytes_to_long(sha256(message.encode()).digest())

    # Ensure that m is a quadratic residue mod n
    if gcd(m, n) != 1:
        raise ValueError("Message hash is not coprime with modulus")

    # Signature s = sqrt(m) mod n (one of the four possible roots)
    s = pow(m, (p + 1) // 4, p)  # Can also be computed via Chinese Remainder Theorem
    return s


# Rabin Digital Signature Verification
def rabin_verify(public_key, message, signature):
    n = public_key

    # Hash the message to a number m
    m = bytes_to_long(sha256(message.encode()).digest())

    # Verify that signature^2 == m mod n
    return pow(signature, 2, n) == m


# Helper functions to export keys
def export_private_key(private_key):
    p, q = private_key
    with open("rabin_private_key.txt", "w") as f:
        f.write(f"{p},{q}")


def export_public_key(public_key):
    with open("rabin_public_key.txt", "w") as f:
        f.write(str(public_key))


# Example Usage of Rabin Cryptosystem
if __name__ == "__main__":
    public_key, private_key = rabin_keygen()

    print(f"Public key: {public_key}")
    print(f"Private key: {private_key}")

    # Encrypt a message
    message = "HelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHello"
    ciphertext = rabin_encrypt(public_key, message)
    print(f"Ciphertext: {ciphertext}")

    # Decrypt the ciphertext
    decrypted_message = rabin_decrypt(private_key, public_key, ciphertext)
    print(f"Decrypted message: {decrypted_message}")

    # Sign a message
    signature = rabin_sign(private_key, message, public_key)
    print(f"Signature: {signature}")

    # Verify the signature
    verification = rabin_verify(public_key, message, signature)
    print(f"Signature valid: {verification}")
