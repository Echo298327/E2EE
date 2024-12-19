from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from logger import init_logger

logger = init_logger('client.encryption')


def encrypt_with_server_public_key(data, server_public_key):
    """
    Encrypt the given data using the server's public key.
    """
    public_key = load_pem_public_key(server_public_key.encode())
    encrypted_data = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    logger.info(f"Encrypted data length (client): {len(encrypted_data)}")
    return encrypted_data