from datetime import datetime, timedelta
from utils.recv import recv_exact
from request_handler import send_response
from utils.status_codes import StatusCodes
from utils.logger import init_logger as logger
from db_manager import (
    get_server_public_key, 
    save_user, 
    save_registration_token,
    get_token_expiry,
    user_exists
)
from auth_encryption import generate_six_digit_code, decrypt_with_server_private_key


logger = logger('server.user_manager')


def generate_registration_token():
    token = generate_six_digit_code()
    # Add 10 minutes to the current time
    expires_at = (datetime.now() + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M')
    save_registration_token(token, expires_at)
    return token


def validate_registration_token(token):
    expires_at_str = get_token_expiry(token)
    if expires_at_str:
        # Use format string for "YYYY-MM-DD HH:MM"
        expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M')
        if datetime.now() < expires_at:
            return True  # Token is valid
    return False  # Token is invalid or expired


def request_registration_token(client_socket, version):
    try:
        # Generate a 6-digit registration token
        token = str(generate_registration_token())

        # Retrieve the server's public key
        public_key = get_server_public_key()
        if not public_key:
            raise ValueError("Server public key not found")

        # Create payload with token and public key
        payload = token.encode() + public_key.encode()
        
        # Send response with payload
        send_response(client_socket, version, StatusCodes.TOKEN_ISSUED.value, payload)
        logger.info("Public key sent with token.")
    except Exception as e:
        logger.error(f"Error during token generation or public key retrieval: {e}")
        send_response(client_socket, version, StatusCodes.SERVER_ERROR.value)


def complete_registration(client_socket, version, user_id, payload_len):
    try:
        # Receive payload
        payload = recv_exact(client_socket, payload_len)

        # Extract token
        token_bytes = payload[:6]
        token = token_bytes.decode('ascii')
        logger.info(f"Extracted token: {token}")

        # Validate token
        if not token.isdigit() or len(token) != 6:
            raise ValueError(f"Invalid token format: {token}")
        if not validate_registration_token(token):
            raise ValueError(f"Invalid or expired token: {token}")

        # Extract encrypted user_id
        encrypted_user_id_len = 256  # Assuming RSA 2048-bit key
        encrypted_user_id = payload[6:6 + encrypted_user_id_len]

        # Extract client public key
        client_public_key = payload[6 + encrypted_user_id_len:].decode()
        logger.info(f"Extracted client public key: {client_public_key[:30]}...")

        # Decrypt user_id
        decrypted_user_id = decrypt_with_server_private_key(encrypted_user_id)

        # Verify user_id matches the header
        if int(decrypted_user_id) != user_id:
            raise ValueError(f"User ID mismatch: header={user_id}, payload={decrypted_user_id}")

        # Check if user already exists
        if user_exists(user_id):
            logger.warning(f"User {user_id} already registered")
            send_response(client_socket, version, StatusCodes.REQUEST_REGISTRATION_COMPLETE.value)
            return

        # Save the user's public key
        save_user(client_public_key, user_id)
        logger.info(f"User {user_id} successfully registered with public key.")

        # Send success response
        send_response(client_socket, version, StatusCodes.REQUEST_REGISTRATION_COMPLETE.value)

    except ValueError as ve:
        logger.error(f"Validation error during registration: {ve}")
        send_response(client_socket, version, StatusCodes.INVALID_TOKEN.value)
    except Exception as e:
        logger.error(f"Unexpected error during registration: {e}")
        send_response(client_socket, version, StatusCodes.SERVER_ERROR.value)
