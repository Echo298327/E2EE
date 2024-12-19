import os
import sqlite3
import struct
from config import settings
from status_codes import StatusCodes


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

