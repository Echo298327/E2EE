import os
from logger import init_logger

logger = init_logger('server.utils')


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


def is_database_initialized() -> bool:
    """Check if the database file exists."""
    db_path = os.path.join(os.getcwd(), 'storage.db')
    return os.path.exists(db_path)
