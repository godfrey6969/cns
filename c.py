import time
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


# Task 1: Keypair Generation Time
def keypair_generation_time():
    # RSA Key Generation
    start_time = time.time()
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    rsa_key_time = time.time() - start_time

    # DSA Key Generation
    start_time = time.time()
    dsa_key = dsa.generate_private_key(key_size=3072)
    dsa_key_time = time.time() - start_time

    # ECDSA Key Generation (using SECP256R1 curve)
    start_time = time.time()
    ecdsa_key = ec.generate_private_key(ec.SECP256R1())
    ecdsa_key_time = time.time() - start_time

    print(f"RSA Key Generation Time: {rsa_key_time:.6f} seconds")
    print(f"DSA Key Generation Time: {dsa_key_time:.6f} seconds")
    print(f"ECDSA Key Generation Time: {ecdsa_key_time:.6f} seconds")

    return rsa_key, dsa_key, ecdsa_key


# Task 2: Signing Time
def signing_speed(rsa_key, dsa_key, ecdsa_key, data):
    # RSA Signing
    start_time = time.time()
    rsa_signature = rsa_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    rsa_sign_time = time.time() - start_time

    # DSA Signing
    start_time = time.time()
    dsa_signature = dsa_key.sign(data, hashes.SHA256())
    dsa_sign_time = time.time() - start_time

    # ECDSA Signing
    start_time = time.time()
    ecdsa_signature = ecdsa_key.sign(data, ec.ECDSA(hashes.SHA256()))
    ecdsa_sign_time = time.time() - start_time

    print(f"RSA Signing Time: {rsa_sign_time:.6f} seconds")
    print(f"DSA Signing Time: {dsa_sign_time:.6f} seconds")
    print(f"ECDSA Signing Time: {ecdsa_sign_time:.6f} seconds")

    return rsa_signature, dsa_signature, ecdsa_signature


# Task 3: Verification Time
def verification_speed(
    rsa_key, dsa_key, ecdsa_key, rsa_signature, dsa_signature, ecdsa_signature, data
):
    rsa_public_key = rsa_key.public_key()
    dsa_public_key = dsa_key.public_key()
    ecdsa_public_key = ecdsa_key.public_key()

    # RSA Verification
    start_time = time.time()
    rsa_public_key.verify(
        rsa_signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    rsa_verify_time = time.time() - start_time

    # DSA Verification
    start_time = time.time()
    dsa_public_key.verify(dsa_signature, data, hashes.SHA256())
    dsa_verify_time = time.time() - start_time

    # ECDSA Verification
    start_time = time.time()
    ecdsa_public_key.verify(ecdsa_signature, data, ec.ECDSA(hashes.SHA256()))
    ecdsa_verify_time = time.time() - start_time

    print(f"RSA Verification Time: {rsa_verify_time:.6f} seconds")
    print(f"DSA Verification Time: {dsa_verify_time:.6f} seconds")
    print(f"ECDSA Verification Time: {ecdsa_verify_time:.6f} seconds")


if __name__ == "__main__":
    # Random data to sign
    data = b"This is a test message for signing."

    print("\nKeypair Generation Speed:")
    rsa_key, dsa_key, ecdsa_key = keypair_generation_time()

    print("\nSigning Speed:")
    rsa_signature, dsa_signature, ecdsa_signature = signing_speed(
        rsa_key, dsa_key, ecdsa_key, data
    )

    print("\nVerification Speed:")
    verification_speed(
        rsa_key, dsa_key, ecdsa_key, rsa_signature, dsa_signature, ecdsa_signature, data
    )
