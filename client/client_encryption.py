from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from utils.logger import init_logger

logger = init_logger('client.encryption')


def encrypt_with_public_key(data, server_public_key):
    """
    Encrypt the given data using the server's public key.
    """
    try:
        public_key = load_pem_public_key(server_public_key.encode())
        data_bytes = data.encode() if isinstance(data, str) else data  # Ensure data is bytes
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


def generate_client_key_pair():
    """
    Generate an RSA key pair for the client.
    Returns the private and public keys in PEM format.
    """
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_key_pem, public_key_pem
    except Exception as e:
        logger.error(f"Key generation error: {e}")
        raise


def decrypt_message(encrypted_message, private_key):
    """
    Decrypt an encrypted message using the client private key.

    Args:
        encrypted_message (bytes): The encrypted message data.
        private_key (bytes): The private key in PEM format used to decrypt the message.

    Returns:
        str: The decrypted message as a string, or None if decryption fails.
    """
    try:
        if not private_key:
            raise ValueError("Private key not provided")
        # Deserialize the private key
        private_key_obj = load_pem_private_key(private_key, password=None)

        # Decrypt the message
        decrypted_message = private_key_obj.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode()

    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return None


def create_signature_with_client_private_key(private_key: bytes, data: bytes) -> bytes:
    """
    Create a digital signature for the given data using the client's private key.

    Args:
        private_key (bytes): The client's private key in PEM format.
        data (bytes): The data to sign (must be in bytes format).

    Returns:
        bytes: The digital signature.
    """
    try:
        private_key_obj = load_pem_private_key(private_key, password=None)

        # Compute the signature
        signature = private_key_obj.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    except Exception as e:
        logger.error(f"Error creating signature: {e}")
        raise




