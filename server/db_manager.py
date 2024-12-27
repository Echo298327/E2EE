import os
import sqlite3
from config import settings
from utils.logger import init_logger
from datetime import datetime, timedelta
from auth_encryption import generate_server_key_pair

logger = init_logger('server.db_manager')


def init_database():
    db_path = os.path.join(os.getcwd(), 'storage.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            sent INTEGER DEFAULT 0
        )
    ''')

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            public_key TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create registration_tokens table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS registration_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL,
            expires_at DATETIME NOT NULL
        )
    ''')

    # Create server_keys table
    cursor.execute('''
         CREATE TABLE IF NOT EXISTS server_keys (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             private_key TEXT NOT NULL,
             public_key TEXT NOT NULL,
             created_at DATETIME DEFAULT CURRENT_TIMESTAMP
         )
     ''')

    initialize_server_keys()
    conn.commit()
    conn.close()


def initialize_server_keys():
    """
    Generate and store a new RSA key pair for the server.
    """
    private_key, public_key = generate_server_key_pair()
    # save the server's public key to a file
    with open('../client/server_public_key.pem', 'wb') as f:
        f.write(public_key.encode('utf-8'))  # Encode the string into bytes
    save_server_key_pair(private_key, public_key)
    logger.info('Server keys initialized')


def save_server_key_pair(private_key, public_key):
    """
    Save the server's key pair to the database.
    """
    db_path = os.path.join(os.getcwd(), 'storage.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Insert key pair into the database
    cursor.execute('''
        INSERT INTO server_keys (private_key, public_key)
        VALUES (?, ?)
    ''', (private_key, public_key))
    conn.commit()


def get_server_public_key():
    # Retrieve the server's public key from the database
    db_path = os.path.join(os.getcwd(), settings.DATABASE_PATH)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT public_key FROM server_keys')
    public_key = cursor.fetchone()[0]
    conn.close()
    return public_key


def is_database_initialized() -> bool:
    """Check if the database file exists."""
    db_path = os.path.join(os.getcwd(), 'storage.db')
    return os.path.exists(db_path)


def save_message(recipient_id, sender_id, message, timestamp):
    """Save a new message to the database."""
    conn = sqlite3.connect(os.path.join(os.getcwd(), settings.DATABASE_PATH))
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO messages (recipient_id, sender_id, message, timestamp, sent) VALUES (?, ?, ?, ?, 0)',
        (recipient_id, sender_id, message, timestamp)
    )
    conn.commit()
    conn.close()


def get_unsent_messages(user_id):
    """Retrieve all unsent messages for a specific user."""
    conn = sqlite3.connect(os.path.join(os.getcwd(), settings.DATABASE_PATH))
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, sender_id, message FROM messages WHERE recipient_id = ? AND sent = 0', 
        (user_id,)
    )
    messages = cursor.fetchall()
    conn.close()
    return messages


def delete_unsent_messages(user_id):
    """Delete all unsent messages for a specific user."""
    conn = sqlite3.connect(os.path.join(os.getcwd(), settings.DATABASE_PATH))
    cursor = conn.cursor()
    cursor.execute('DELETE FROM messages WHERE recipient_id = ? AND sent = 0', (user_id,))
    conn.commit()
    conn.close()


def mark_messages_as_sent(message_ids):
    """Mark multiple messages as sent."""
    conn = sqlite3.connect(os.path.join(os.getcwd(), settings.DATABASE_PATH))
    cursor = conn.cursor()
    cursor.executemany(
        'UPDATE messages SET sent = 1 WHERE id = ?', 
        [(msg_id,) for msg_id in message_ids]
    )
    conn.commit()
    conn.close()


def save_user(public_key, user_id):
    """Save a new user to the database with specific ID."""
    conn = sqlite3.connect(os.path.join(os.getcwd(), settings.DATABASE_PATH))
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (id, public_key) VALUES (?, ?)', (user_id, public_key))
    conn.commit()
    conn.close()


def validate_user(public_key):
    """Check if a user exists with the given public key."""
    conn = sqlite3.connect(os.path.join(os.getcwd(), settings.DATABASE_PATH))
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE public_key = ?', (public_key,))
    user = cursor.fetchone()
    conn.close()
    return user is not None


def save_registration_token(token, expires_at):
    """Save a new registration token to the database."""
    conn = sqlite3.connect(os.path.join(os.getcwd(), settings.DATABASE_PATH))
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO registration_tokens (token, expires_at) VALUES (?, ?)', 
        (token, expires_at)
    )
    conn.commit()
    conn.close()


def get_token_expiry(token):
    """Get the expiration time for a registration token."""
    conn = sqlite3.connect(os.path.join(os.getcwd(), settings.DATABASE_PATH))
    cursor = conn.cursor()
    cursor.execute('SELECT expires_at FROM registration_tokens WHERE token = ?', (token,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None


def user_exists(user_id):
    """Check if a user exists with the given ID."""
    conn = sqlite3.connect(os.path.join(os.getcwd(), settings.DATABASE_PATH))
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user is not None


def get_user_public_key(user_id):
    """Retrieve the public key for a specific user."""
    conn = sqlite3.connect(os.path.join(os.getcwd(), settings.DATABASE_PATH))
    cursor = conn.cursor()
    cursor.execute('SELECT public_key FROM users WHERE id = ?', (user_id,))
    public_key = cursor.fetchone()
    conn.close()
    return public_key[0] if public_key else None


def delete_registration_token(token):
    """Delete a registration token from the database."""
    conn = sqlite3.connect(os.path.join(os.getcwd(), settings.DATABASE_PATH))
    cursor = conn.cursor()
    cursor.execute('DELETE FROM registration_tokens WHERE token = ?', (token,))
    conn.commit()
    conn.close()


def delete_expired_registration_tokens():
    """Delete all expired registration tokens from the database."""
    conn = sqlite3.connect(os.path.join(os.getcwd(), settings.DATABASE_PATH))
    cursor = conn.cursor()

    # Get the current timestamp
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Delete tokens where the expires_at time has passed
    cursor.execute('''
        DELETE FROM registration_tokens 
        WHERE expires_at <= ?
    ''', (current_time,))

    conn.commit()
    conn.close()
