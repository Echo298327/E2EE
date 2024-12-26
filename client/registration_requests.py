import os
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
        if not hasattr(client, 'id') or not hasattr(client, 'private_key'):
            raise ValueError("Client object must have 'id' and 'private_key' attributes")

        # Create a socket connection
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_host, server_port))
        logger.info(f"Connected to server at {server_host}:{server_port}")

        # Request unsent messages
        op = StatusCodes.REQUEST_CONNECTION.value
        header_format = '!I B B H'
        header_data = struct.pack(header_format, int(client.id), version, op, 0)  # payload_len = 0
        client_socket.send(header_data)

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
        if server_public_key == StatusCodes.REQUEST_REGISTRATION_COMPLETE.value:
            # load client key pair from files
            load_client_key_pair(client)
            return True
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

        if response_status == StatusCodes.REQUEST_REGISTRATION_COMPLETE.value:
            logger.warning(f"User {user_id} already registered.")
            return None, StatusCodes.REQUEST_REGISTRATION_COMPLETE.value

        # Check for expected status
        if response_status != StatusCodes.TOKEN_ISSUED.value:
            logger.error(f"Unexpected response status: {response_status}")
            return None, None

        # Receive and process payload
        payload = recv_exact(client_socket, payload_len)
        token = payload[:6].decode()  # First 6 bytes for the token
        server_public_key = payload[6:].decode()  # Remaining bytes for the public key
        if not validate_server_public_key(server_public_key):
            logger.critical("the received server public key is invalid. could be a MITM attack")
            raise ValueError("Invalid server public key")
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

        # before generating key pair check if the client already has a key pair saved in the files
        if os.path.exists(f"{client.id}_private.pem") and os.path.exists(f"{client.id}_public.pem"):
            load_client_key_pair(client)
            logger.info("Client key pair loaded successfully from files")
        else:
            # Generate client key pair
            private_key, public_key = generate_client_key_pair()
            logger.info("Generated client key pair successfully")
            # Save client key pair to files pem
            with open(f"{client.id}_private.pem", "wb") as f:
                f.write(private_key)

            with open(f"{client.id}_public.pem", "wb") as f:
                f.write(public_key)
            client.private_key = private_key
            client.public_key = public_key

        # Encrypt user_id
        data_to_encrypt = f"{user_id}"
        encrypted_user_id = encrypt_with_public_key(data_to_encrypt, server_public_key)
        logger.info("Encrypted user_id successfully")

        # Combine payload: token + encrypted_user_id + client_public_key
        payload = token_bytes + encrypted_user_id + client.public_key
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


def load_client_key_pair(client):
    """
    Load the client's RSA key pair from files.
    """
    try:
        with open(f"{client.id}_private.pem", "rb") as f:
            private_key = f.read()
        with open(f"{client.id}_public.pem", "rb") as f:
            public_key = f.read()
        client.private_key = private_key
        client.public_key = public_key
        logger.info("Client key pair loaded successfully from files")
    except FileNotFoundError as e:
        logger.error(f"Key pair files not found: {e}")
    except Exception as e:
        logger.error(f"Error loading client key pair: {e}")
        raise


def validate_server_public_key(server_public_key):
    """
    Validate the server's public key.
    """
    try:
        with open(f"server_public_key.pem", "rb") as f:
            public_key = f.read()
        return server_public_key == public_key.decode()
    except Exception as e:
        logger.error(f"Invalid server public key: {e}")
        return False