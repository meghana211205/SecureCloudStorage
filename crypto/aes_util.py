from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

def encrypt_file(file_bytes):
    """
    Encrypts file bytes using AES-GCM.
    Returns: ciphertext, nonce, tag, aes_key
    """
    aes_key = get_random_bytes(32) # AES-256
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_bytes)
    return ciphertext, cipher.nonce, tag, aes_key

def decrypt_file(ciphertext, key, nonce, tag):
    """
    Decrypts AES-GCM encrypted file bytes.
    Returns: original plaintext file_bytes
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def encrypt_file_with_key(file_bytes, aes_key):
    """
    Encrypts file bytes using an externally provided AES key (e.g., from ML-KEM).
    Returns: ciphertext, nonce, tag
    """
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_bytes)
    return ciphertext, cipher.nonce, tag
