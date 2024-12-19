import socket
import struct
from utils.status_codes import StatusCodes
from utils.logger import init_logger
from utils.recv import recv_exact
from client_encryption import encrypt_with_server_public_key

logger = init_logger('client.manager')


def request_registration_token(server_host, server_port, user_id, version):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_host, server_port))
        logger.info(f"Connected to server at {server_host}:{server_port}")

        # Request token
        op = StatusCodes.REQUEST_REGISTRATION_TOKEN.value
        header_format = '!I B B H'
        header_data = struct.pack(header_format, user_id, version, op, 0)  # payload_len = 0
        client_socket.send(header_data)

        # Receive response
        response_header_format = '!B H H'
        response_header_size = struct.calcsize(response_header_format)
        response_header_data = client_socket.recv(response_header_size)
        response_version, response_status, payload_len = struct.unpack(response_header_format, response_header_data)

        if response_status == StatusCodes.TOKEN_ISSUED.value:
            payload = client_socket.recv(payload_len)
            token = payload[:6].decode()  # Extract token
            server_public_key = payload[6:].decode()  # Extract public key
            return token, server_public_key

        logger.error(f"Failed to receive token. Status: {response_status}")
        return None, None

    except Exception as e:
        logger.error(f"Error in request_registration_token: {e}")
        return None, None
    finally:
        client_socket.close()
        logger.info("Client socket closed.")


def receive_response(client_socket):
    """
    Receive and parse a standardized response from the server.
    Returns:
        tuple: (version, status_code, payload)
    """
    try:
        # Receive response header
        response_header_format = '!B H H'
        response_header_size = struct.calcsize(response_header_format)
        response_header_data = client_socket.recv(response_header_size)
        
        version, status, payload_len = struct.unpack(response_header_format, response_header_data)
        logger.info(f"Received response header: version={version}, status={status}, payload_len={payload_len}")
        
        # Receive payload if any
        payload = b''
        if payload_len > 0:
            payload = recv_exact(client_socket, payload_len)
            
        return version, status, payload
    except Exception as e:
        logger.error(f"Error receiving response: {e}")
        raise


def register_user_request_with_token(server_host, server_port, user_id, client_public_key, token, server_public_key):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_host, server_port))
        logger.info(f"Connected to server at {server_host}:{server_port}")

        # Prepare payload
        token_str = str(token).zfill(6)[:6]
        token_bytes = token_str.encode('ascii')
        
        data_to_encrypt = f"{user_id}|{client_public_key}"
        encrypted_data = encrypt_with_server_public_key(data_to_encrypt, server_public_key)
        
        payload = token_bytes + encrypted_data
        payload_len = len(payload)
        
        # Validate payload size
        if payload_len > 1048576:  # 1MB max
            raise ValueError(f"Payload too large: {payload_len} bytes")
        
        # Prepare header
        op_code = StatusCodes.REQUEST_SECURE_REGISTRATION_COMPLETE.value

        header_data = bytearray()
        header_data.extend(struct.pack('!I', user_id))  # 4 bytes for user_id
        header_data.extend(struct.pack('!B', 1))        # 1 byte for version
        header_data.extend(struct.pack('!B', op_code))  # 1 byte for op
        header_data.extend(struct.pack('!H', payload_len))  # 2 bytes for length
        
        # Log the header details
        logger.info(f"Sending header - user_id: {user_id}, version: 1, " +
                    f"op: {op_code}, length: {payload_len}")

        # Send header and payload separately
        client_socket.sendall(header_data)
        client_socket.sendall(payload)

        # Receive response
        version, status, response_payload = receive_response(client_socket)
        logger.info(f"Registration response status: {status}")
        
        return status == StatusCodes.REQUEST_REGISTRATION_COMPLETE.value

    except Exception as e:
        logger.error(f"Registration request failed: {e}")
        return False
    finally:
        client_socket.close()


def register_request(server_host, server_port, user_id, version, client_public_key):
    client_socket = None
    try:
        # Create single socket connection for entire registration process
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_host, server_port))
        logger.info(f"Connected to server at {server_host}:{server_port}")

        # Step 1: Request the registration token and server public key
        token, server_public_key = request_registration_token_with_socket(client_socket, user_id, version)
        if not token or not server_public_key:
            logger.error("Failed to obtain registration token or server public key. Exiting registration process.")
            return False

        logger.info(f"Successfully received token and server public key")
        
        # Create new socket for the second phase
        client_socket.close()
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_host, server_port))
        
        # Step 2: Use the token to complete registration
        success = register_user_request_with_token_socket(
            client_socket, user_id, client_public_key, token, server_public_key
        )
        return success

    except ConnectionAbortedError as e:
        logger.error(f"Connection was aborted: {e}")
        return False
    except ConnectionResetError as e:
        logger.error(f"Connection was reset: {e}")
        return False
    except Exception as e:
        logger.error(f"Error in register_request: {e}")
        return False
    finally:
        if client_socket:
            try:
                client_socket.close()
                logger.info("Client socket closed.")
            except Exception as e:
                logger.error(f"Error closing socket: {e}")


def request_registration_token_with_socket(client_socket, user_id, version):
    try:
        # Request token
        op = StatusCodes.REQUEST_REGISTRATION_TOKEN.value
        header_format = '!I B B H'
        header_data = struct.pack(header_format, user_id, version, op, 0)  # payload_len = 0
        client_socket.send(header_data)

        # Receive response
        response_header_format = '!B H H'
        response_header_size = struct.calcsize(response_header_format)
        response_header_data = client_socket.recv(response_header_size)
        response_version, response_status, payload_len = struct.unpack(response_header_format, response_header_data)

        if response_status == StatusCodes.TOKEN_ISSUED.value:
            payload = client_socket.recv(payload_len)
            token = payload[:6].decode()  # Extract token
            server_public_key = payload[6:].decode()  # Extract public key
            return token, server_public_key

        logger.error(f"Failed to receive token. Status: {response_status}")
        return None, None

    except Exception as e:
        logger.error(f"Error in request_registration_token: {e}")
        return None, None


def register_user_request_with_token_socket(client_socket, user_id, client_public_key, token, server_public_key):
    try:
        # Prepare payload
        token_str = str(token).zfill(6)[:6]
        token_bytes = token_str.encode('ascii')
        
        data_to_encrypt = f"{user_id}|{client_public_key}"
        encrypted_data = encrypt_with_server_public_key(data_to_encrypt, server_public_key)
        
        payload = token_bytes + encrypted_data
        payload_len = len(payload)
        
        # Validate payload size
        if payload_len > 1048576:  # 1MB max
            raise ValueError(f"Payload too large: {payload_len} bytes")
        
        # Prepare header
        op_code = StatusCodes.REQUEST_SECURE_REGISTRATION_COMPLETE.value

        header_data = bytearray()
        header_data.extend(struct.pack('!I', user_id))  # 4 bytes for user_id
        header_data.extend(struct.pack('!B', 1))        # 1 byte for version
        header_data.extend(struct.pack('!B', op_code))  # 1 byte for op
        header_data.extend(struct.pack('!H', payload_len))  # 2 bytes for length
        
        # Log the header details
        logger.info(f"Sending header - user_id: {user_id}, version: 1, " +
                    f"op: {op_code}, length: {payload_len}")

        # Send header and payload separately
        client_socket.sendall(header_data)
        client_socket.sendall(payload)

        # Receive response
        version, status, response_payload = receive_response(client_socket)
        logger.info(f"Registration response status: {status}")
        
        return status == StatusCodes.REQUEST_REGISTRATION_COMPLETE.value

    except Exception as e:
        logger.error(f"Registration request failed: {e}")
        return False


