import os
import random
import sqlite3
from utils.logger import init_logger
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


logger = init_logger('server.auth_encryption')


def generate_six_digit_code():
    return random.randint(100000, 999999)


def decrypt_with_server_private_key(encrypted_data):
    """
    Decrypt the given data using the server's private key.
    """
    try:
        db_path = os.path.join(os.getcwd(), 'storage.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Fetch private key from the database
        cursor.execute('SELECT private_key FROM server_keys ORDER BY created_at DESC LIMIT 1')
        private_key_pem = cursor.fetchone()[0]
        conn.close()

        private_key = load_pem_private_key(private_key_pem.encode(), password=None)
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_data.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        raise


def generate_server_key_pair():
    """
    Generate a new RSA key pair for the server.
    Returns the private and public keys as PEM strings.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return private_key_pem, public_key_pem


def validate_signature_with_client_public_key(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Validate the digital signature of the message using the client's public key.

    Args:
        public_key (bytes): The client's public key in PEM format.
        message (bytes): The encrypted message to verify.
        signature (bytes): The digital signature.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        # Load the public key from PEM format
        public_key_obj = load_pem_public_key(public_key)

        # Verify the signature
        public_key_obj.verify(
            signature,                  # The signature to verify
            message,                    # The original message (encrypted message in this case)
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask Generation Function
                salt_length=padding.PSS.MAX_LENGTH           # Maximum salt length
            ),
            hashes.SHA256()             # Hashing algorithm used during signing
        )
        logger.info("Signature validated successfully.")
        return True
    except Exception as e:
        logger.error(f"Signature validation failed: {e}")
        return False





