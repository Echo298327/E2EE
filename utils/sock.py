import socket

from utils.logger import init_logger

logger = init_logger('client.sock')


def close_socket(sock):
    """
    Safely shuts down and closes a socket, handling all edge cases.
    """
    try:
        # Check if the socket is valid and connected
        if sock.fileno() == -1:  # Socket is already closed
            logger.warning("Socket is already closed, no action needed.")
            return

        # Attempt to shut down the socket
        sock.shutdown(socket.SHUT_RDWR)
        logger.info("Socket shutdown successfully.")
    except OSError as e:
        if e.errno == 57:  # Errno 57: Socket is not connected
            logger.warning("Socket is not connected, skipping shutdown.")
        else:
            logger.warning(f"Error during socket shutdown: {e}")
    finally:
        try:
            sock.close()
            logger.info("Socket closed.")
        except Exception as e:
            logger.error(f"Error while closing the socket: {e}")