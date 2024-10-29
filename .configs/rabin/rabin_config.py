from Crypto.Util import number


class Rabin:
    def __init__(self, bit_length=512):
        self.bit_length = bit_length
        self.public_key, self.private_key = self.generate_keypair(bit_length)

    def generate_keypair(self, bit_length):
        p = self.generate_prime(bit_length // 2)
        q = self.generate_prime(bit_length // 2)
        n = p * q  # Public key modulus
        return n, (p, q)

    def generate_prime(self, bits):
        while True:
            p = number.getPrime(bits)
            if p % 4 == 3:
                return p

    def encrypt(self, message):
        n = self.public_key
        ciphertext = pow(message, 2, n)
        return ciphertext

    def decrypt(self, ciphertext):
        p, q = self.private_key
        mp = pow(ciphertext, (p + 1) // 4, p)
        mq = pow(ciphertext, (q + 1) // 4, q)

        gcd, yp, yq = self.egcd(p, q)
        r1 = (yp * p * mq + yq * q * mp) % self.public_key
        r2 = self.public_key - r1
        r3 = (yp * p * mq - yq * q * mp) % self.public_key
        r4 = self.public_key - r3

        return r1, r2, r3, r4

    def egcd(self, a, b):
        x0, x1, y0, y1 = 1, 0, 0, 1
        while b != 0:
            q, a, b = a // b, b, a % b
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1
        return a, x0, y0

    def int_to_bytes(self, number):
        return number.to_bytes((number.bit_length() + 7) // 8, byteorder="big")

    def bytes_to_int(self, data):
        return int.from_bytes(data, byteorder="big")


if __name__ == "__main__":
    rabin = Rabin()
    message = b"Hello, world!"

    # Convert message to an integer for encryption
    message_int = rabin.bytes_to_int(message)
    ciphertext = rabin.encrypt(message_int)
    plaintexts = rabin.decrypt(ciphertext)

    print(f"Message (original): {message}")
    print(f"Ciphertext: {ciphertext}")

    # Find the correct plaintext by directly comparing with the original message
    found_match = False
    for i, plaintext in enumerate(plaintexts):
        # Convert the plaintext integer back to bytes
        plaintext_bytes = rabin.int_to_bytes(plaintext)

        # Debug output for each possible plaintext
        print(f"Plaintext option {i + 1}: {plaintext}")
        print(f"Plaintext bytes (decoded): {plaintext_bytes}")

        # Check if this matches the original message
        if plaintext_bytes == message:
            print(
                f"Decrypted message (matching): {plaintext_bytes.decode(errors='ignore')}"
            )
            found_match = True
            break

    if not found_match:
        print("No matching decrypted message found.")
