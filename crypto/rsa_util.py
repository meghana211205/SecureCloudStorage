from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import base64

def generate_keys():
    """
    Generates a 2048-bit RSA key pair.
    Returns: private_key_pem (str), public_key_pem (str)
    """
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return private_key, public_key

def encrypt_aes_key(aes_key, public_key_pem):
    """
    Encrypts the AES key using the recipient's RSA public key.
    Returns: encrypted_aes_key (bytes)
    """
    recipient_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

def decrypt_aes_key(encrypted_aes_key, private_key_pem):
    """
    Decrypts the AES key using the owner's RSA private key.
    Returns: aes_key (bytes)
    """
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return aes_key
