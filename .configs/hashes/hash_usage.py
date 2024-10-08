import hash_config

# Generate a dataset of 100 random strings (with lengths between 8 and 16 characters)
dataset = hash_config.generate_dataset(size=100)

# Run the analysis
results = hash_config.analyze_hashing_performance(dataset)

# Print results
print("MD5 Average Time: ", results["md5"]["avg_time"])
print("MD5 Collisions: ", results["md5"]["collisions"])

print("SHA-1 Average Time: ", results["sha1"]["avg_time"])
print("SHA-1 Collisions: ", results["sha1"]["collisions"])

print("SHA-256 Average Time: ", results["sha256"]["avg_time"])
print("SHA-256 Collisions: ", results["sha256"]["collisions"])
