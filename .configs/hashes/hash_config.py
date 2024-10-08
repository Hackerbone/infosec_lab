import hashlib
import random
import string
import time
from collections import defaultdict


# Generate a random string of a given length
def generate_random_string(length=8):
    letters = string.ascii_letters + string.digits
    return "".join(random.choice(letters) for i in range(length))


# Generate a dataset of random strings
def generate_dataset(size=50, min_length=8, max_length=16):
    return [
        generate_random_string(random.randint(min_length, max_length))
        for _ in range(size)
    ]


# Hashing using MD5
def md5_hash(data):
    return hashlib.md5(data.encode()).hexdigest()


# Hashing using SHA-1
def sha1_hash(data):
    return hashlib.sha1(data.encode()).hexdigest()


# Hashing using SHA-256
def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


# Measure hash computation time for a given hash function
def measure_time(hash_function, data):
    start_time = time.time()
    hash_value = hash_function(data)
    end_time = time.time()
    return hash_value, end_time - start_time


# Detect collisions in the hashed dataset
def detect_collisions(hash_values):
    collision_dict = defaultdict(list)
    collisions = []
    for i, hash_value in enumerate(hash_values):
        collision_dict[hash_value].append(i)
        if len(collision_dict[hash_value]) > 1:
            collisions.append(hash_value)
    return collisions


# Perform the experiment
def analyze_hashing_performance(dataset):
    md5_times, sha1_times, sha256_times = [], [], []
    md5_hashes, sha1_hashes, sha256_hashes = [], [], []

    for data in dataset:
        # Measure and store MD5 hash time and value
        md5_hash_val, md5_time = measure_time(md5_hash, data)
        md5_times.append(md5_time)
        md5_hashes.append(md5_hash_val)

        # Measure and store SHA-1 hash time and value
        sha1_hash_val, sha1_time = measure_time(sha1_hash, data)
        sha1_times.append(sha1_time)
        sha1_hashes.append(sha1_hash_val)

        # Measure and store SHA-256 hash time and value
        sha256_hash_val, sha256_time = measure_time(sha256_hash, data)
        sha256_times.append(sha256_time)
        sha256_hashes.append(sha256_hash_val)

    # Detect collisions for each hashing algorithm
    md5_collisions = detect_collisions(md5_hashes)
    sha1_collisions = detect_collisions(sha1_hashes)
    sha256_collisions = detect_collisions(sha256_hashes)

    # Performance results
    results = {
        "md5": {
            "avg_time": sum(md5_times) / len(md5_times),
            "collisions": md5_collisions,
        },
        "sha1": {
            "avg_time": sum(sha1_times) / len(sha1_times),
            "collisions": sha1_collisions,
        },
        "sha256": {
            "avg_time": sum(sha256_times) / len(sha256_times),
            "collisions": sha256_collisions,
        },
    }

    return results
