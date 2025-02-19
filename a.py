import os
import time
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Function to create a large file of a given size (in MB)
def create_large_file(file_path, size_in_mb):
    with open(file_path, 'wb') as file:
        file.write(os.urandom(size_in_mb * 1024 * 1024))  # Write random data of the specified size

# HMAC-SHA256 implementation
def hmac_sha256(key, file_data):
    h = hmac.new(key, file_data, hashlib.sha256)
    return h.hexdigest()

def compute_hmac_sha256(file_path, key):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    start_time = time.time()
    tag = hmac_sha256(key, file_data)
    elapsed_time = time.time() - start_time
    return tag, elapsed_time

# AES-128-GMAC implementation
def aes_gmac(key, file_data, nonce):
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, file_data, b"")

def compute_aes_gmac(file_path, key, nonce):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    start_time = time.time()
    tag = aes_gmac(key, file_data, nonce)
    elapsed_time = time.time() - start_time
    return tag, elapsed_time

# Main execution and performance comparison
if __name__ == "__main__":
    # Parameters
    file_path = 'large_file.txt'
    file_size_mb = 10  # Adjust this to create a file of a different size (in MB)

    # Create a large file of the specified size
    print(f"Creating a file of size {file_size_mb} MB...")
    create_large_file(file_path, file_size_mb)
    print(f"File {file_path} created.\n")

    # Generating a 128-bit key for AES and a key for HMAC
    aes_key = os.urandom(16)  # 128-bit key for AES-128-GMAC
    hmac_key = os.urandom(32)  # 256-bit key for HMAC-SHA256
    nonce = os.urandom(12)  # 12-byte nonce for AES-GCM

    # Compute HMAC-SHA256
    print("Computing HMAC-SHA256...")
    hmac_tag, hmac_time = compute_hmac_sha256(file_path, hmac_key)
    print(f"HMAC-SHA256 tag: {hmac_tag}")
    print(f"HMAC-SHA256 time: {hmac_time:.6f} seconds\n")

    # Compute AES-128-GMAC
    print("Computing AES-128-GMAC...")
    aes_tag, aes_time = compute_aes_gmac(file_path, aes_key, nonce)
    print(f"AES-128-GMAC tag: {aes_tag}")
    print(f"AES-128-GMAC time: {aes_time:.6f} seconds\n")

    # Summary comparison
    print("Performance Summary:")
    print(f"HMAC-SHA256 took {hmac_time:.6f} seconds.")
    print(f"AES-128-GMAC took {aes_time:.6f} seconds.")
    if aes_time < hmac_time:
        print("AES-128-GMAC outperformed HMAC-SHA256.")
    else:
        print("HMAC-SHA256 outperformed AES-128-GMAC.")
