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

        # Extract and validate token
        token_bytes = payload[:6]
        encrypted_data = payload[6:]
        
        token = token_bytes.decode('ascii')

        if not token.isdigit() or len(token) != 6:
            raise ValueError(f"Invalid token format: {token}")
        if not validate_registration_token(token):
            raise ValueError(f"Invalid or expired token: {token}")
        
        # Process the encrypted portion of the payload
        decrypted_data = decrypt_with_server_private_key(encrypted_data)
        decrypted_user_id, client_public_key = decrypted_data.split('|')
        
        # Verify user_id matches
        if int(decrypted_user_id) != user_id:
            raise ValueError(f"User ID mismatch: header={user_id}, payload={decrypted_user_id}")
        
        # Check if user already exists
        if user_exists(user_id):
            logger.warning(f"User {user_id} already registered")
            send_response(client_socket, version, StatusCodes.REQUEST_REGISTRATION_COMPLETE.value)
            return
            
        # Complete registration
        save_user(client_public_key, user_id)
        send_response(client_socket, version, StatusCodes.REQUEST_REGISTRATION_COMPLETE.value)
        logger.info(f"Registration completed for user_id={user_id}")
        
    except Exception as e:
        logger.error(f"Error during registration: {e}")
        send_response(client_socket, version, StatusCodes.SERVER_ERROR.value)
