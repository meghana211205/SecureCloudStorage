from Cryptodome.Hash import SHA256

def generate_hash(file_bytes):
    """
    Generates a SHA-256 hash of the file bytes.
    Returns: hex string of the hash
    """
    h = SHA256.new()
    h.update(file_bytes)
    return h.hexdigest()
