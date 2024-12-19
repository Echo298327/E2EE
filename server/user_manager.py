import os
import sqlite3
from config import settings
from utils.recv import recv_exact
from request_handler import send_response
from utils.status_codes import StatusCodes
from utils.logger import init_logger as logger
from datetime import datetime, timedelta
from db_manager import get_server_public_key
from auth_encryption import generate_six_digit_code, decrypt_with_server_private_key


logger = logger('server.user_manager')


def save_user(public_key):
    db_path = os.path.join(os.getcwd(), settings.DATABASE_PATH)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (public_key) VALUES (?)', (public_key,))
    conn.commit()
    conn.close()


def validate_user(public_key):
    db_path = os.path.join(os.getcwd(), settings.DATABASE_PATH)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE public_key = ?', (public_key,))
    user = cursor.fetchone()
    conn.close()
    return user is not None


def generate_registration_token():
    token = generate_six_digit_code()
    # Add 10 minutes to the current time
    expires_at = (datetime.now() + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M')
    db_path = os.path.join(os.getcwd(), settings.DATABASE_PATH)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO registration_tokens (token, expires_at) VALUES (?, ?)', (token, expires_at))
    conn.commit()
    conn.close()
    return token


def validate_registration_token(token):
    db_path = os.path.join(os.getcwd(), settings.DATABASE_PATH)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT expires_at FROM registration_tokens WHERE token = ?', (token,))
    result = cursor.fetchone()
    conn.close()
    if result:
        # Use format string for "YYYY-MM-DD HH:MM"
        expires_at = datetime.strptime(result[0], '%Y-%m-%d %H:%M')
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
        
        logger.info(f"Registration token issued: {token}")
        logger.info("Public key sent with token.")
    except Exception as e:
        logger.error(f"Error during token generation or public key retrieval: {e}")
        send_response(client_socket, version, StatusCodes.SERVER_ERROR.value)


def complete_registration(client_socket, version, user_id, payload_len):
    try:
        # Receive payload
        payload = recv_exact(client_socket, payload_len)
        logger.info(f"Received payload of length: {len(payload)}")
        
        # Extract and validate token
        token_bytes = payload[:6]
        encrypted_data = payload[6:]
        
        token = token_bytes.decode('ascii')
        logger.info(f"Extracted token: {token}")
        
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
        
        # Complete registration
        save_user(client_public_key)
        send_response(client_socket, version, StatusCodes.REQUEST_REGISTRATION_COMPLETE.value)
        logger.info(f"Registration completed for user_id={user_id}")
        
    except Exception as e:
        logger.error(f"Error during registration: {e}")
        send_response(client_socket, version, StatusCodes.SERVER_ERROR.value)
