import threading
import socket
from datetime import datetime
from config import settings
from utils.logger import init_logger
from manager import handle_client_connection
from db_manager import init_database, is_database_initialized, delete_expired_registration_tokens

logger = init_logger('server.app')


def start_server():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow port reuse
        server.bind((settings.SERVER_HOST, int(settings.SERVER_PORT)))
        server.listen(10)  # Allow up to 10 pending connections
        logger.info(f'Server listening on {settings.SERVER_URL}')
        while True:
            try:
                client_sock, address = server.accept()
                logger.info(f'Accepted connection from {address}')
                time_stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                # Handle the connection in a new thread
                thread = threading.Thread(
                    target=handle_client_connection, args=(client_sock, time_stamp)
                )
                thread.start()
            except Exception as e:
                logger.error(f"Error handling client connection: {e}")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        server.close()


if __name__ == "__main__":
    if not is_database_initialized():
        init_database()
    delete_expired_registration_tokens()
    start_server()


