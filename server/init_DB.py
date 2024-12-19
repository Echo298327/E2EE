import sqlite3
import os
from auth_encryption import generate_server_key_pair


def initialize_server_keys():
    """
    Generate and store a new RSA key pair for the server.
    """
    private_key, public_key = generate_server_key_pair()
    save_server_key_pair(private_key, public_key)


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
