from utils.logger import init_logger
from utils.status_codes import StatusCodes
import struct

logger = init_logger('server.request_handler')


def send_response(client_socket, version, status_code, payload=b''):
    """
    Send a standardized response to the client.
    Args:
        client_socket: The socket connection to the client
        version: Protocol version
        status_code: StatusCodes enum value
        payload: Optional bytes payload (default empty)
    """
    try:
        payload_len = len(payload)
        response_header = struct.pack('!B H H', version, status_code, payload_len)

        if payload_len > 0:
            response = response_header + payload
        else:
            response = response_header

        client_socket.send(response)
        logger.info(f"Sent response: version={version}, status={status_code}, payload_len={payload_len}")
    except Exception as e:
        logger.error(f"Error sending response: {e}")
        # Send error response without payload
        error_response = struct.pack('!B H H', version, StatusCodes.SERVER_ERROR.value, 0)
        client_socket.send(error_response)
