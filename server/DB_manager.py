import sqlite3
import os
from config import settings


def get_server_public_key():
    # Retrieve the server's public key from the database
    db_path = os.path.join(os.getcwd(), settings.DATABASE_PATH)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT public_key FROM server_keys')
    public_key = cursor.fetchone()[0]
    conn.close()
    return public_key
