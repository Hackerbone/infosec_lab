import elgamal.elgamal_config as elgamal_config
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class Hospital:
    def __init__(self):
        self.records = {}  # Encrypted patient records
        self.encrypted_keys = (
            {}
        )  # Store encrypted symmetric keys for doctors and nurses
        self.signatures = {}  # Store digital signatures for integrity checks
        self.doctors = {}  # Dictionary to store doctor keys
        self.nurses = {}  # Dictionary to store nurse keys

    def add_doctor(self, doctor_id):
        public_key, private_key = elgamal_config.elgamal_keygen()
        self.doctors[doctor_id] = {"public_key": public_key, "private_key": private_key}
        print(f"Doctor {doctor_id} added.")

    def add_nurse(self, nurse_id):
        public_key, private_key = elgamal_config.elgamal_keygen()
        self.nurses[nurse_id] = {"public_key": public_key, "private_key": private_key}
        print(f"Nurse {nurse_id} added.")

    def _encrypt_symmetric_key(self, aes_key, public_key):
        """Encrypt AES symmetric key using ElGamal public key"""
        aes_key_as_int = bytes_to_long(aes_key)
        encrypted_key = elgamal_config.elgamal_encrypt(public_key, aes_key_as_int)
        return encrypted_key

    def _decrypt_symmetric_key(self, encrypted_key, private_key, public_key):
        """Decrypt AES symmetric key using ElGamal private key"""
        decrypted_key_int = elgamal_config.elgamal_decrypt(
            private_key, public_key, encrypted_key
        )
        aes_key = long_to_bytes(decrypted_key_int)
        return aes_key

    def add_patient_record(self, patient_id, record, doctor_id):
        """Only doctors can add and modify patient records"""
        if doctor_id not in self.doctors:
            raise PermissionError("Only doctors can add or modify patient records.")

        doctor_public_key = self.doctors[doctor_id]["public_key"]

        # Generate a symmetric AES key
        aes_key = get_random_bytes(16)

        # Encrypt the patient record with the AES key
        cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(record.encode())

        # Encrypt the AES key with the doctor's public key and each nurse's public key
        encrypted_keys = {
            "doctor": self._encrypt_symmetric_key(aes_key, doctor_public_key)
        }
        for nurse_id in self.nurses:
            nurse_public_key = self.nurses[nurse_id]["public_key"]
            encrypted_keys[nurse_id] = self._encrypt_symmetric_key(
                aes_key, nurse_public_key
            )

        # Digitally sign the record for integrity using the doctor's private key
        doctor_private_key = self.doctors[doctor_id]["private_key"]
        signature = elgamal_config.elgamal_sign(
            doctor_private_key, record, doctor_public_key
        )

        # Store the encrypted record, AES encrypted keys, and signature
        self.records[patient_id] = {
            "ciphertext": ciphertext,
            "tag": tag,
            "nonce": cipher.nonce,
        }
        self.encrypted_keys[patient_id] = encrypted_keys
        self.signatures[patient_id] = signature

        print(f"Patient {patient_id}'s record added by Doctor {doctor_id}.")

    def view_patient_record(self, user_id, patient_id):
        """Both doctors and nurses can view patient records"""
        if user_id in self.doctors:
            private_key = self.doctors[user_id]["private_key"]
            public_key = self.doctors[user_id]["public_key"]
        elif user_id in self.nurses:
            private_key = self.nurses[user_id]["private_key"]
            public_key = self.nurses[user_id]["public_key"]
        else:
            raise PermissionError("Only doctors and nurses can view patient records.")

        # Retrieve the encrypted record and encrypted AES key
        record_data = self.records.get(patient_id)
        if not record_data:
            raise ValueError(f"No record found for Patient {patient_id}.")
        encrypted_key = self.encrypted_keys[patient_id].get(
            user_id if user_id in self.nurses else "doctor"
        )

        # Decrypt the AES key using the user's private key
        aes_key = self._decrypt_symmetric_key(encrypted_key, private_key, public_key)

        # Decrypt the patient record using the AES key
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=record_data["nonce"])
        decrypted_record = cipher.decrypt_and_verify(
            record_data["ciphertext"], record_data["tag"]
        ).decode()

        # Verify the integrity of the record using the stored signature
        signature = self.signatures.get(patient_id)

        print(f"Signature generated for patient record: {signature}")
        print(f"Decrypted record: {decrypted_record}")
        print(f"Signature being verified: {signature}")

        if not elgamal_config.elgamal_verify(public_key, decrypted_record, signature):
            raise ValueError("Record integrity verification failed!")

        print(f"Record for Patient {patient_id}: {decrypted_record}")
        return decrypted_record

    def modify_patient_record(self, doctor_id, patient_id, new_record):
        """Only doctors can modify patient records"""
        if doctor_id not in self.doctors:
            raise PermissionError("Only doctors can modify patient records.")

        # Same process as adding a record, but for modification
        self.add_patient_record(patient_id, new_record, doctor_id)
        print(f"Patient {patient_id}'s record modified by Doctor {doctor_id}.")


# Example usage of Hospital system
if __name__ == "__main__":
    hospital = Hospital()

    # Adding doctors and nurses
    hospital.add_doctor("doc1")
    hospital.add_nurse("nurse1")

    # Doctor adds a patient record
    hospital.add_patient_record("patient1", "Patient 1 has a mild fever", "doc1")

    # Nurse tries to view the patient record
    hospital.view_patient_record("nurse1", "patient1")

    # Doctor modifies the patient record
    hospital.modify_patient_record(
        "doc1", "patient1", "Patient 1 has been prescribed medication"
    )

    # Nurse views the modified patient record
    hospital.view_patient_record("nurse1", "patient1")
