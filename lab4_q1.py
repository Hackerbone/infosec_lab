from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import os
import time


class DRMSystem:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.master_key_pair = None
        self.content_keys = {}
        self.access_control = {}
        self.logs = []

    def generate_master_key(self):
        self.master_key_pair = ElGamal.generate(self.key_size, get_random_bytes)
        self.log("Master key pair generated.")

    def encrypt_content(self, content_id, content):
        h = SHA256.new(content).digest()
        encrypted_content = self.master_key_pair.encrypt(h, get_random_bytes(16))
        self.content_keys[content_id] = encrypted_content
        self.log(f"Content {content_id} encrypted.")

    def distribute_key(self, customer_id, content_id):
        # Example access control: Limited-time access
        self.access_control[(customer_id, content_id)] = time.time() + 3600
        self.log(f"Access granted to {customer_id} for content {content_id}.")

    def revoke_access(self, customer_id, content_id):
        if (customer_id, content_id) in self.access_control:
            del self.access_control[(customer_id, content_id)]
            self.log(f"Access revoked for {customer_id} for content {content_id}.")

    def key_revocation(self):
        self.generate_master_key()
        self.log("Master key revoked and renewed.")

    def check_access(self, customer_id, content_id):
        if (customer_id, content_id) in self.access_control:
            access_time = self.access_control[(customer_id, content_id)]
            if time.time() <= access_time:
                return True
        return False

    def secure_store_key(self):
        # Simple demonstration: Write key to file with restricted access
        with open("private_key.pem", "wb") as f:
            f.write(self.master_key_pair.export_key())
        os.chmod("private_key.pem", 0o600)
        self.log("Master private key securely stored.")

    def log(self, message):
        self.logs.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")
        print(message)  # For demonstration purposes


# Example Usage:
drm = DRMSystem()
drm.generate_master_key()
drm.encrypt_content("content1", b"Some digital content")
drm.distribute_key("customer1", "content1")
drm.revoke_access("customer1", "content1")
drm.key_revocation()
drm.secure_store_key()
