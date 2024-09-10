from Crypto.Util import number
import time


# Rabin Cryptosystem Key Generation, Encryption, and Decryption
class RabinCryptosystem:
    def __init__(self, key_size=1024):
        self.key_size = key_size

    def generate_key_pair(self):
        p = number.getPrime(self.key_size // 2)
        q = number.getPrime(self.key_size // 2)
        n = p * q
        return (n,), (p, q)  # Public key (n), Private key (p, q)

    def encrypt(self, public_key, message):
        n = public_key[0]
        m = int.from_bytes(message.encode("utf-8"), "big")
        return (m**2) % n

    def decrypt(self, private_key, ciphertext):
        p, q = private_key
        n = p * q
        # Calculate roots using Chinese Remainder Theorem
        mp = pow(ciphertext, (p + 1) // 4, p)
        mq = pow(ciphertext, (q + 1) // 4, q)
        yp, yq = number.inverse(q, p), number.inverse(p, q)
        r1 = (yp * p * mq + yq * q * mp) % n
        r2 = (yp * p * mq - yq * q * mp) % n
        return [r1, n - r1, r2, n - r2]


# Key Management and Logging Functions
class KeyManager:
    def __init__(self, key_size=1024):
        self.keys = {}
        self.logs = []
        self.rabin = RabinCryptosystem(key_size)

    def generate_keys(self, facility_id):
        public_key, private_key = self.rabin.generate_key_pair()
        self.keys[facility_id] = {"public_key": public_key, "private_key": private_key}
        self.log(f"Keys generated for {facility_id}.")
        return public_key

    def distribute_keys(self, facility_id):
        keys = self.keys.get(facility_id)
        if keys:
            self.log(f"Keys distributed to {facility_id}.")
            return keys["public_key"], keys["private_key"]
        self.log(f"Keys not found for {facility_id}.")
        return None

    def log(self, message):
        entry = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}"
        self.logs.append(entry)
        print(entry)


# Example Usage
km = KeyManager()
facility_id = "hospital1"

# Key Generation and Distribution
public_key = km.generate_keys(facility_id)
public_key, private_key = km.distribute_keys(facility_id)

# Encrypt and Decrypt Example
message = "datadatadatadatadata"
ciphertext = km.rabin.encrypt(public_key, message)
print(f"Encrypted: {ciphertext}")
possible_plaintexts = km.rabin.decrypt(private_key, ciphertext)

# Print Valid Decrypted Results
print("Possible decrypted messages:")
for i, pt in enumerate(possible_plaintexts):
    try:
        # Convert the decrypted integer to bytes
        decoded_bytes = int.to_bytes(pt, (pt.bit_length() + 7) // 8, "big")
        try:
            # Attempt to decode bytes to text
            decoded_message = decoded_bytes.decode("utf-8")
            print(f"Decrypted possibility {i+1}: {decoded_message}")
        except UnicodeDecodeError:
            # If decoding to text fails, just print the hex
            print(f"Decrypted possibility {i+1}: (hex) {decoded_bytes.hex()}")
    except Exception as e:
        print(f"Decrypted possibility {i+1}: Unable to decode - {e}")
