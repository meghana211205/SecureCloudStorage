import time
import os
from crypto.aes_util import encrypt_file_with_key, decrypt_file
from crypto.kem_util import generate_kem_keys, encapsulate_key_kem, decapsulate_key_kem
from crypto.hash_util import generate_hash

def run_workflow_benchmark(file_size_mb, iterations):
    print(f"\n--- Benchmarking {file_size_mb}MB File Workflow (Average over {iterations} Iterations) ---")
    
    # Generate dummy file bytes exactly matching the requested MB size
    dummy_file_bytes = os.urandom(file_size_mb * 1024 * 1024)
    
    # 1. Prepare User's Keys (Simulating a user who is already registered/logged in)
    kem_public_key, kem_private_key = generate_kem_keys()

    # ==========================
    # UPLOAD WORKFLOW
    # ==========================
    start_time = time.time()
    for _ in range(iterations):
        # Step 1: Hash the original file
        original_hash = generate_hash(dummy_file_bytes)
        
        # Step 2: Encapsulate Key (Generates AES key and Ciphertext puzzle)
        aes_key, encrypted_aes_key_puzzle = encapsulate_key_kem(kem_public_key)

        # Step 3: AES Encrypt the large file using the KEM-derived key
        ciphertext, nonce, tag = encrypt_file_with_key(dummy_file_bytes, aes_key)
        
    upload_time = time.time() - start_time
    avg_upload_ms = (upload_time / iterations) * 1000

    # Generate one final valid payload set to use for the Download benchmark
    original_hash = generate_hash(dummy_file_bytes)
    aes_key, encrypted_aes_key_puzzle = encapsulate_key_kem(kem_public_key)
    ciphertext, nonce, tag = encrypt_file_with_key(dummy_file_bytes, aes_key)

    # ==========================
    # DOWNLOAD WORKFLOW
    # ==========================
    start_time = time.time()
    for _ in range(iterations):
        # Step 1: Decapsulate AES key using Private Key
        decrypted_aes_key = decapsulate_key_kem(encrypted_aes_key_puzzle, kem_private_key)
        
        # Step 2: AES Decrypt the large file
        plaintext = decrypt_file(ciphertext, decrypted_aes_key, nonce, tag)
        
        # Step 3: Hash to verify integrity
        decrypted_hash = generate_hash(plaintext)
        
    download_time = time.time() - start_time
    avg_download_ms = (download_time / iterations) * 1000

    # ==========================
    # RESULTS
    # ==========================
    print(f"Total Upload Time   : {avg_upload_ms:>8.2f} milliseconds")
    print(f"Total Download Time : {avg_download_ms:>8.2f} milliseconds")

def main():
    print("=" * 64)
    print("   SECURE CLOUD STORAGE - FULL WORKFLOW BENCHMARK   ")
    print("           (Upgraded: AES-256 + ML-KEM-768)         ")
    print("=" * 64)
    
    # We will test realistic sizes exactly like the RSA script
    run_workflow_benchmark(file_size_mb=1, iterations=100)
    run_workflow_benchmark(file_size_mb=10, iterations=20)

    print("\n" + "=" * 64)
    print("Done! Save these numbers to compare with RSA for your project report.")
    print("=" * 64)

if __name__ == '__main__':
    main()
