from Crypto.Util import number
import time
import os


# Subsystem: Key Management
class KeyManager:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.keys = {}  # {facility_id: {'public_key': (n, b), 'private_key': (p, q)}}
        self.logs = []

    def generate_keys(self, facility_id):
        p = number.getPrime(self.key_size // 2)
        q = number.getPrime(self.key_size // 2)
        n = p * q
        b = number.getRandomRange(1, n)
        public_key = (n, b)
        private_key = (p, q)
        self.keys[facility_id] = {"public_key": public_key, "private_key": private_key}
        self.log(f"Keys generated for {facility_id}.")
        return public_key

    def distribute_key(self, facility_id):
        if facility_id in self.keys:
            self.log(f"Key distributed to {facility_id}.")
            return (
                self.keys[facility_id]["public_key"],
                self.keys[facility_id]["private_key"],
            )
        else:
            self.log(f"Key distribution failed for {facility_id}. Not found.")
            return None

    def revoke_key(self, facility_id):
        if facility_id in self.keys:
            del self.keys[facility_id]
            self.log(f"Keys revoked for {facility_id}.")

    def renew_keys(self):
        for facility_id in list(self.keys.keys()):
            self.generate_keys(facility_id)
        self.log("Keys renewed for all facilities.")

    def secure_store_key(self, facility_id):
        if facility_id in self.keys:
            with open(f"{facility_id}_private_key.pem", "wb") as f:
                f.write(str(self.keys[facility_id]["private_key"]).encode())
            os.chmod(f"{facility_id}_private_key.pem", 0o600)
            self.log(f"Private key securely stored for {facility_id}.")

    def log(self, message):
        log_entry = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}"
        self.logs.append(log_entry)
        print(log_entry)


# Main Service Class Integrating Key Management and Compliance
class HealthcareKeyService:
    def __init__(self):
        self.key_manager = KeyManager()

    def initialize_service(self):
        self.key_manager.log("Healthcare Key Management Service initialized.")

    def generate_and_distribute_keys(self, facility_id):
        self.key_manager.generate_keys(facility_id)
        return self.key_manager.distribute_key(facility_id)

    def revoke_and_renew_keys(self):
        self.key_manager.renew_keys()

    def store_keys_securely(self, facility_id):
        self.key_manager.secure_store_key(facility_id)


# Example Usage:
service = HealthcareKeyService()
service.initialize_service()
service.generate_and_distribute_keys("hospital1")
service.key_manager.revoke_key("hospital1")
service.revoke_and_renew_keys()
service.store_keys_securely("hospital1")
