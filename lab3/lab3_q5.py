import time
import random
from hashlib import sha256

# Prime number (p) and generator (g)
p = 23  # small prime number for demonstration, in practice, use a large prime
g = 5  # generator


def generate_private_key():
    """Generate a private key."""
    return random.randint(1, p - 1)


def generate_public_key(private_key):
    """Generate a public key."""
    return pow(g, private_key, p)


def compute_shared_secret(private_key, other_public_key):
    """Compute the shared secret key."""
    return pow(other_public_key, private_key, p)


# Measure time taken for key generation and exchange
start_time = time.time()

# Peer 1
private_key_1 = generate_private_key()
public_key_1 = generate_public_key(private_key_1)

# Peer 2
private_key_2 = generate_private_key()
public_key_2 = generate_public_key(private_key_2)

# Key exchange
shared_secret_1 = compute_shared_secret(private_key_1, public_key_2)
shared_secret_2 = compute_shared_secret(private_key_2, public_key_1)

# Derive a shared key (optional, using SHA-256)
shared_key_1 = sha256(str(shared_secret_1).encode()).hexdigest()
shared_key_2 = sha256(str(shared_secret_2).encode()).hexdigest()

end_time = time.time()

# Check if the shared keys match
assert shared_key_1 == shared_key_2

# Output the results
print(f"Public Key 1: {public_key_1}")
print(f"Public Key 2: {public_key_2}")
print(f"Shared Key: {shared_key_1}")
print(f"Time taken: {end_time - start_time} seconds")
