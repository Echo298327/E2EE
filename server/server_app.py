import socket
from datetime import datetime
from config import settings
from logger import init_logger
from manager import handle_client_connection
from db_manager import init_database
from utils import is_database_initialized

logger = init_logger('server.app')


def start_server():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((settings.SERVER_HOST, int(settings.SERVER_PORT)))
        server.listen(5)
        logger.info(f'Server listening on {settings.SERVER_URL}')
        while True:
            try:
                time_stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                client_sock, address = server.accept()
                logger.info(f'Accepted connection from {address}')
                handle_client_connection(client_sock, time_stamp)
            except Exception as e:
                logger.error(f"Error handling client connection: {e}")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        server.close()


if __name__ == "__main__":
    if not is_database_initialized():
        init_database()
    start_server()
