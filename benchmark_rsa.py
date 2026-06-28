import time
import os
from crypto.aes_util import encrypt_file, decrypt_file
from crypto.rsa_util import generate_keys, encrypt_aes_key, decrypt_aes_key
from crypto.hash_util import generate_hash

def run_workflow_benchmark(file_size_mb, iterations):
    print(f"\n--- Benchmarking {file_size_mb}MB File Workflow (Average over {iterations} Iterations) ---")
    
    # Generate dummy file bytes exactly matching the requested MB size
    dummy_file_bytes = os.urandom(file_size_mb * 1024 * 1024)
    
    # 1. Prepare User's Keys (Simulating a user who is already registered/logged in)
    private_key_pem, public_key_pem = generate_keys()

    # ==========================
    # UPLOAD WORKFLOW
    # ==========================
    start_time = time.time()
    for _ in range(iterations):
        # Step 1: Hash the original file
        original_hash = generate_hash(dummy_file_bytes)
        
        # Step 2: AES Encrypt the large file (Generates ciphertext, nonce, tag, random aes_key)
        ciphertext, nonce, tag, aes_key = encrypt_file(dummy_file_bytes)
        
        # Step 3: RSA Encrypt the small AES key
        encrypted_aes_key = encrypt_aes_key(aes_key, public_key_pem)
        
    upload_time = time.time() - start_time
    avg_upload_ms = (upload_time / iterations) * 1000

    # Generate one final valid payload set to use for the Download benchmark
    original_hash = generate_hash(dummy_file_bytes)
    ciphertext, nonce, tag, aes_key = encrypt_file(dummy_file_bytes)
    encrypted_aes_key = encrypt_aes_key(aes_key, public_key_pem)


    # ==========================
    # DOWNLOAD WORKFLOW
    # ==========================
    start_time = time.time()
    for _ in range(iterations):
        # Step 1: RSA Decrypt the AES key
        decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key_pem)
        
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
    print("              (Baseline: AES-256 + RSA-2048)        ")
    print("=" * 64)
    
    # We will test realistic sizes. The iterations are kept reasonable so it finishes quickly.
    run_workflow_benchmark(file_size_mb=1, iterations=100)
    run_workflow_benchmark(file_size_mb=10, iterations=20)

    print("\n" + "=" * 64)
    print("Done! Save these baseline numbers for your final project report.")
    print("When we upgrade to Post-Quantum ML-KEM, we will run this again")
    print("to see the exact difference in total upload/download times.")
    print("=" * 64)

if __name__ == '__main__':
    main()
