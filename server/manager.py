import os
import sqlite3
import struct
from datetime import datetime, timedelta
from config import settings
from logger import init_logger
from status_codes import StatusCodes
from auth_encryption import generate_six_digit_code, decrypt_with_server_private_key
from DB_manager import get_server_public_key


logger = init_logger('server.manager')


def recv_exact(client_socket, length):
    data = b""
    while len(data) < length:
        logger.info(f"Receiving... {len(data)} of {length} bytes received so far.")
        packet = client_socket.recv(length - len(data))
        if not packet:
            raise ConnectionError("Socket connection broken")
        data += packet
    logger.info(f"Full encrypted data received: {len(data)} bytes")
    return data


# Message Functions
def save_message(recipient_id, sender_id, message, timestamp):
    db_path = os.path.join(os.getcwd(), settings.DATABASE_PATH)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO messages (recipient_id, sender_id, message, timestamp, sent) VALUES (?, ?, ?, ?, 0)',
                   (recipient_id, sender_id, message, timestamp))
    conn.commit()
    conn.close()


def get_unsent_messages(user_id):
    db_path = os.path.join(os.getcwd(), settings.DATABASE_PATH)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT id, sender_id, message FROM messages WHERE recipient_id = ? AND sent = 0', (user_id,))
    messages = cursor.fetchall()
    conn.close()
    return messages


def deliver_unsent_messages(client_socket, version, user_id):
    unsent_messages = get_unsent_messages(user_id)
    if not unsent_messages:
        response = struct.pack('B H', version, StatusCodes.NO_UNSENT_MESSAGES.value)
        logger.info(f"No unsent messages for user: {user_id}")
        client_socket.send(response)
        return


def send_message(client_socket, message_len, version, sender_id, recipient_id, timestamp):
    message = client_socket.recv(message_len).decode()
    save_message(recipient_id, sender_id, message, timestamp)
    response = struct.pack('B H', version, StatusCodes.MESSAGE_SAVED.value)
    logger.info(f"Unsent message saved for recipient: {recipient_id} at {timestamp}")
    client_socket.send(response)


def mark_messages_as_sent(message_ids):
    db_path = os.path.join(os.getcwd(), settings.DATABASE_PATH)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.executemany('UPDATE messages SET sent = 1 WHERE id = ?', [(msg_id,) for msg_id in message_ids])
    conn.commit()
    conn.close()


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


# Secure Registration and Messaging

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


def handle_client_connection(client_socket, time_stamp):
    try:
        header_format = 'I B B H'
        header_size = struct.calcsize(header_format)
        header_data = client_socket.recv(header_size)
        if not header_data:
            raise ConnectionError("Failed to receive header data")

        user_id, version, op, message_len = struct.unpack(header_format, header_data)
        logger.info(f"Received request: user_id={user_id}, version={version}, op={op}, message_len={message_len}")

        if op == StatusCodes.REQUEST_SEND_MESSAGE.value:
            recipient_id = client_socket.recv(4)
            send_message(client_socket, message_len, version, user_id, struct.unpack('I', recipient_id)[0], time_stamp)
        elif op == StatusCodes.REQUEST_GET_UNSENT_MESSAGES.value:
            deliver_unsent_messages(client_socket, version, user_id)
        elif op == StatusCodes.REQUEST_REGISTRATION_TOKEN.value:
            request_registration_token(client_socket, version)
        elif op == StatusCodes.REQUEST_SECURE_REGISTRATION_COMPLETE.value:
            complete_registration(client_socket, version)
        else:
            response = struct.pack('B H', version, StatusCodes.SERVER_ERROR.value)
            client_socket.send(response)
            logger.error(f"Unknown operation: {op}")
    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        client_socket.close()
