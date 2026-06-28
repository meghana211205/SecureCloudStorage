from mlkem.ml_kem import ML_KEM
from mlkem.parameter_set import ML_KEM_768

# Initialize the Pure-Python ML-KEM explicitly using the NIST 768 parameter set
kem_instance = ML_KEM(ML_KEM_768)

def generate_kem_keys():
    """
    Generates a Post-Quantum ML-KEM-768 public/private key pair 
    using the pure Python mlkem package (No C-Compilers needed!)
    """
    try:
        public_key, private_key = kem_instance.key_gen()
        return public_key, private_key
            
    except Exception as e:
        raise RuntimeError(f"Failed to generate ML-KEM keys: {str(e)}")


def encapsulate_key_kem(public_key_bytes):
    """
    Generates a 256-bit shared secret (for AES) and encapsulates it inside a ciphertext.
    """
    try:
        shared_secret, ciphertext = kem_instance.encaps(public_key_bytes)
        return shared_secret, ciphertext
            
    except Exception as e:
        raise RuntimeError(f"Failed to encapsulate key: {str(e)}")


def decapsulate_key_kem(ciphertext_bytes, private_key_bytes):
    """
    Decapsulates the ciphertext using the private key to magically uncover the 256-bit shared secret.
    """
    try:
        shared_secret = kem_instance.decaps(private_key_bytes, ciphertext_bytes)
        return shared_secret
            
    except Exception as e:
        raise RuntimeError(f"Failed to decapsulate key: {str(e)}")
