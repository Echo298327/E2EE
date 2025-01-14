import socket
import struct
from utils.logger import init_logger

logger = init_logger('utils.recv')


def recv_exact(client_socket, length):
    """
    Receive exactly `length` bytes from the socket.
    Raises ConnectionError if connection is broken unexpectedly.
    Handles graceful client disconnections and resets.
    """
    # Sanity check for length
    if length > 1048576:  # 1MB max
        raise ValueError(f"Requested length {length} exceeds maximum allowed")

    data = b""  # Ensure binary data
    while len(data) < length:
        try:
            # Calculate the remaining bytes to read
            remaining = length - len(data)

            # Read in chunks of 8KB or less
            packet = client_socket.recv(min(remaining, 8192))
            if not packet:  # Client closed the connection
                if len(data) == 0:
                    # logger.warning("Client closed connection before any data was received.")
                    return data  # Return empty bytes
                else:
                    raise ConnectionError("Socket connection broken after partial data received")

            # logger.warning(f"Received packet of size: {len(packet)}, remaining: {remaining - len(packet)}")
            data += packet

        except ConnectionResetError as e:
            logger.info(f"Client reset the connection: {e}")
            if len(data) == 0:
                raise ConnectionError("No data received before connection reset")
            return data  # Return partial data if available

        except socket.timeout as e:
            logger.error(f"Socket timeout while receiving data: {e}")
            raise ConnectionError(f"Socket timeout while receiving data: {e}")

        except socket.error as e:
            logger.error(f"Socket error while receiving data: {e}")
            raise ConnectionError(f"Socket error while receiving data: {e}")

        except Exception as e:
            logger.error(f"Unexpected error while receiving data: {e}")
            raise ConnectionError(f"Unexpected error while receiving data: {e}")

    # logger.info(f"Received exact data of length: {length}")
    return data


def recv_header(client_socket, header_format):
    """
    Receive and unpack a header with the given format.
    Returns the unpacked header values.
    """
    header_size = struct.calcsize(header_format)
    header_data = recv_exact(client_socket, header_size)

    try:
        return struct.unpack(header_format, header_data)
    except struct.error as e:
        raise ValueError(f"Failed to unpack header: {e}")