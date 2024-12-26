import socket
import struct
from utils.status_codes import StatusCodes
from utils.logger import init_logger
from utils.recv import recv_exact
from client_encryption import encrypt_with_public_key, generate_client_key_pair, decrypt_message

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


def parse_unsent_messages(payload):
    """
    Parse the aggregated payload of unsent messages into a list of tuples.
    Args:
        payload (bytes): Binary payload containing unsent messages.
    Returns:
        list: A list of tuples (message_id, sender_id, message_data).
    """
    messages = []
    offset = 0
    while offset < len(payload):
        # Extract message_id (4 bytes), sender_id (4 bytes), and message length (2 bytes)
        message_id, sender_id, message_len = struct.unpack_from('!I I H', payload, offset)
        offset += 10  # Advance by the size of the header (4+4+2 bytes)

        # Extract the message data
        message_data = payload[offset:offset + message_len]
        offset += message_len

        messages.append((message_id, sender_id, message_data))
    return messages


def connection_request(server_host, server_port, client, version):
    """
    Establish a persistent connection to the server and optionally request unsent messages for the specified user.
    Returns the connected socket for further operations.
    """
    try:
        # Create a socket connection
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_host, server_port))
        logger.info(f"Connected to server at {server_host}:{server_port}")

        # Request unsent messages
        op = StatusCodes.REQUEST_CONNECTION.value
        header_format = '!I B B H'
        header_data = struct.pack(header_format, int(client.id), version, op, 0)  # payload_len = 0
        client_socket.send(header_data)
        logger.info(f"Request for unsent messages sent for user_id={client.id}")

        # Receive the response header
        response_header_format = '!B H H'
        response_header_size = struct.calcsize(response_header_format)
        response_header_data = recv_exact(client_socket, response_header_size)
        response_version, response_status, payload_len = struct.unpack(response_header_format, response_header_data)
        logger.info(f"Received response header: version={response_version}, status={response_status}, payload_len={payload_len}")

        # Handle response
        if response_status == StatusCodes.MESSAGE_DELIVERED.value:
            # Process unsent messages if any
            payload = recv_exact(client_socket, payload_len)
            unsent_messages = parse_unsent_messages(payload)
            logger.info(f"Received {len(unsent_messages)} unsent messages.")
            for message in unsent_messages:
                message_data = decrypt_message(message[2], client.private_key)
                logger.info(f"Decrypted message: {message_data}")
        elif response_status == StatusCodes.SUCCESSFUL_CONNECTION.value:
            logger.info("No unsent messages found.")

        # Return the connected socket
        return client_socket

    except Exception as e:
        logger.error(f"Error in connection_request: {e}")
        if client_socket:
            client_socket.close()
        raise


def register_request(client_socket, client, version):
    client_id = int(client.id)
    try:
        # Create single socket connection for entire registration process
        # Step 1: Request the registration token and server public key
        token, server_public_key = request_registration_token_with_socket(client_socket, client_id, version)
        if not token or not server_public_key:
            logger.error("Failed to obtain registration token or server public key. Exiting registration process.")
            return False

        logger.info(f"Successfully received token and server public key")

        # Step 2: Use the token to complete registration
        success = register_user_request_with_token_socket(
            client_socket, client, token, server_public_key
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


def request_registration_token_with_socket(client_socket, user_id, version):
    try:
        # Request token
        op = StatusCodes.REQUEST_REGISTRATION_TOKEN.value
        header_format = '!I B B H'
        header_data = struct.pack(header_format, user_id, version, op, 0)  # payload_len = 0
        client_socket.send(header_data)
        logger.info(f"Sent request for registration token: user_id={user_id}, version={version}, op={op}")

        # Receive response header
        response_header_format = '!B H H'
        response_header_size = struct.calcsize(response_header_format)
        response_header_data = recv_exact(client_socket, response_header_size)

        # Unpack response header
        response_version, response_status, payload_len = struct.unpack(response_header_format, response_header_data)
        logger.info(f"Received response header: version={response_version}, status={response_status}, payload_len={payload_len}")

        # Check for expected status
        if response_status != StatusCodes.TOKEN_ISSUED.value:
            logger.error(f"Unexpected response status: {response_status}")
            return None, None

        # Receive and process payload
        payload = recv_exact(client_socket, payload_len)
        token = payload[:6].decode()  # First 6 bytes for the token
        server_public_key = payload[6:].decode()  # Remaining bytes for the public key
        logger.info(f"Successfully received token and server public key.")
        return token, server_public_key

    except struct.error as e:
        logger.error(f"Unpacking error: {e}")
        return None, None
    except Exception as e:
        logger.error(f"Error in request_registration_token_with_socket: {e}")
        return None, None


def register_user_request_with_token_socket(client_socket, client, token, server_public_key):
    try:
        user_id = int(client.id)
        # Prepare token
        token_str = str(token).zfill(6)[:6]
        token_bytes = token_str.encode('ascii')

        # Generate client key pair
        private_key, public_key = generate_client_key_pair()
        logger.info("Generated client key pair successfully")

        # Save client key pair to files
        client.private_key = private_key
        client.public_key = public_key

        # Encrypt user_id
        data_to_encrypt = f"{user_id}"
        encrypted_user_id = encrypt_with_public_key(data_to_encrypt, server_public_key)
        logger.info("Encrypted user_id successfully")

        # Combine payload: token + encrypted_user_id + client_public_key
        payload = token_bytes + encrypted_user_id + public_key
        payload_len = len(payload)

        # Validate payload size
        if payload_len > 1048576:  # Limit: 1MB
            raise ValueError(f"Payload too large: {payload_len} bytes")

        # Prepare header
        op_code = StatusCodes.REQUEST_SECURE_REGISTRATION_COMPLETE.value
        header_format = '>I B B H'
        header_data = struct.pack(header_format, user_id, 1, op_code, payload_len)

        # Log header details
        logger.info(f"Sending header - user_id: {user_id}, version: 1, op: {op_code}, length: {payload_len}")

        # Send header and payload
        client_socket.sendall(header_data)
        client_socket.sendall(payload)
        logger.info("Header and payload sent successfully")

        # Receive response
        response_version, response_status, response_payload = receive_response(client_socket)
        logger.info(f"Registration response status: {response_status}")

        return response_status == StatusCodes.REQUEST_REGISTRATION_COMPLETE.value

    except Exception as e:
        logger.error(f"Registration request failed: {e}")
        return False


