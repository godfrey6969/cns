import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES encryption function (both AES-128 and AES-256)
def aes_encrypt(file_path, key, nonce):
    aesgcm = AESGCM(key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    start_time = time.time()
    ciphertext = aesgcm.encrypt(nonce, file_data, b"")  # Encrypt with an empty associated data
    elapsed_time = time.time() - start_time
    return ciphertext, elapsed_time

# Main execution and performance comparison
if __name__ == "__main__":
    file_path = 'testfile.bin'  # 100MB file path

    # Generating nonces and keys for AES-128 and AES-256
    aes_128_key = os.urandom(16)  # 128-bit key
    aes_256_key = os.urandom(32)  # 256-bit key
    nonce = os.urandom(12)  # 12-byte nonce for GCM mode

    # Encrypt using AES-128
    print("Encrypting using AES-128...")
    aes_128_ciphertext, aes_128_time = aes_encrypt(file_path, aes_128_key, nonce)
    print(f"AES-128 encryption time: {aes_128_time:.6f} seconds\n")

    # Encrypt using AES-256
    print("Encrypting using AES-256...")
    aes_256_ciphertext, aes_256_time = aes_encrypt(file_path, aes_256_key, nonce)
    print(f"AES-256 encryption time: {aes_256_time:.6f} seconds\n")

    # Summary comparison
    print("Performance Comparison:")
    print(f"AES-128 took {aes_128_time:.6f} seconds.")
    print(f"AES-256 took {aes_256_time:.6f} seconds.")
    
    time_difference = aes_256_time - aes_128_time
    percentage_diff = (time_difference / aes_128_time) * 100
    print(f"AES-256 is {percentage_diff:.2f}% slower than AES-128.")

    # Explain the performance difference
    print("\nExplanation of performance difference:")
    print("AES-256 is slower than AES-128 primarily because of its increased key schedule complexity.")
    print("AES-256 has more rounds (14 rounds) than AES-128 (10 rounds), which means more computational effort.")
    print("The increased complexity ensures higher security, but comes at the cost of additional processing time.")
