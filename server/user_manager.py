import os
import sqlite3
import struct
from config import settings
from utils import recv_exact
from status_codes import StatusCodes
from logger import init_logger as logger
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
        token = str(generate_registration_token())  # Convert the integer token to a string

        # Retrieve the server's public key
        public_key = get_server_public_key()
        if not public_key:
            raise ValueError("Server public key not found")

        # Encode the public key and token as payload
        token_encoded = token.encode()
        public_key_encoded = public_key.encode()
        payload = token_encoded + public_key_encoded
        payload_len = len(payload)

        # Respond with the token and public key in a single payload
        response = struct.pack('B H H', version, StatusCodes.TOKEN_ISSUED.value, payload_len) + payload
        client_socket.send(response)

        logger.info(f"Registration token issued: {token}")
        logger.info(f"Public key sent with token.")
    except Exception as e:
        logger.error(f"Error during token generation or public key retrieval: {e}")
        response = struct.pack('B H', version, StatusCodes.SERVER_ERROR.value)
        client_socket.send(response)


def complete_registration(client_socket, version):
    try:
        # Receive token and encrypted payload
        token = client_socket.recv(6).decode()
        encrypted_len = struct.unpack('H', client_socket.recv(2))[0]
        encrypted_data = recv_exact(client_socket, encrypted_len)  # Ensure full data is received

        # Validate token
        if not validate_registration_token(token):
            response = struct.pack('B H', version, StatusCodes.INVALID_TOKEN.value)
            client_socket.send(response)
            logger.error(f"Invalid or expired token: {token}")
            return

        # Decrypt payload
        decrypted_data = decrypt_with_server_private_key(encrypted_data)
        user_id, client_public_key = decrypted_data.split('|')
        logger.info(f"Decrypted payload: user_id={user_id}, client_public_key={client_public_key}")

        # Save the client public key
        save_user(client_public_key)

        # Send success response
        response = struct.pack('B H', version, StatusCodes.REQUEST_REGISTRATION_COMPLETE.value)
        client_socket.send(response)
        logger.info(f"User registration completed successfully for user_id={user_id}.")
    except Exception as e:
        logger.error(f"Error during registration: {e}")
        response = struct.pack('B H', version, StatusCodes.SERVER_ERROR.value)
        client_socket.send(response)
