import hashlib
import time
import random
import string
from collections import defaultdict

# Function to generate a random string of fixed length
def generate_random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Function to compute hash values
def compute_hashes(strings, hash_algo):
    hash_dict = {}
    for s in strings:
        hash_obj = hash_algo()
        hash_obj.update(s.encode())
        hash_value = hash_obj.hexdigest()
        hash_dict[s] = hash_value
    return hash_dict

# Function to detect collisions
def detect_collisions(hash_dict):
    reverse_hashes = defaultdict(list)
    collisions = []
    for s, h in hash_dict.items():
        reverse_hashes[h].append(s)
    
    for hash_value, strs in reverse_hashes.items():
        if len(strs) > 1:
            collisions.append((hash_value, strs))
    
    return collisions

# Generate dataset
def generate_dataset(num_strings=50, length=10):
    return [generate_random_string(length) for _ in range(num_strings)]

# Measure time taken for hashing
def measure_time_and_collisions(strings, hash_algos):
    results = {}
    
    for algo_name, hash_algo in hash_algos.items():
        start_time = time.time()
        hashes = compute_hashes(strings, hash_algo)
        end_time = time.time()
        
        collision_info = detect_collisions(hashes)
        
        results[algo_name] = {
            'time_taken': end_time - start_time,
            'collisions': collision_info
        }
    
    return results

# Main function
def main():
    # Define hash algorithms
    hash_algos = {
        'MD5': hashlib.md5,
        'SHA-1': hashlib.sha1,
        'SHA-256': hashlib.sha256
    }
    
    # Generate dataset
    num_strings = 5000
    dataset = generate_dataset(num_strings)
    
    # Measure performance and collisions
    results = measure_time_and_collisions(dataset, hash_algos)
    
    # Print results
    for algo_name, result in results.items():
        print(f"Algorithm: {algo_name}")
        print(f"Time taken: {result['time_taken']:.8f} seconds")
        print(f"Collisions detected: {len(result['collisions'])}")
        for collision in result['collisions']:
            print(f"Hash: {collision[0]} -> Strings: {collision[1]}")
        print()

if __name__ == '__main__':
    main()

"""
OUTPUT:

Algorithm: MD5
Time taken: 0.00200009 seconds
Collisions detected: 0

Algorithm: SHA-1
Time taken: 0.00199342 seconds
Collisions detected: 0

Algorithm: SHA-256
Time taken: 0.00199986 seconds
Collisions detected: 0

"""