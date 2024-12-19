import socket
import struct


def recv_exact(client_socket, length):
    """
    Receive exactly length bytes from the socket.
    Raises ConnectionError if connection is broken.
    """
    # Sanity check for length
    if length > 1048576:  # 1MB max
        raise ValueError(f"Requested length {length} exceeds maximum allowed")

    data = b""
    while len(data) < length:
        try:
            packet = client_socket.recv(min(length - len(data), 8192))  # Read in chunks of 8KB
            if not packet:
                raise ConnectionError("Socket connection broken")
            data += packet
        except socket.error as e:
            raise ConnectionError(f"Socket error while receiving data: {e}")

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