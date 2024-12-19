from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from utils.logger import init_logger

logger = init_logger('client.encryption')


def encrypt_with_server_public_key(data, server_public_key):
    """
    Encrypt the given data using the server's public key.
    """
    try:
        public_key = load_pem_public_key(server_public_key.encode())
        # Convert data to bytes if it's a string
        data_bytes = data.encode() if isinstance(data, str) else data
        
        encrypted_data = public_key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_data
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        raise
