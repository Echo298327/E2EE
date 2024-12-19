import socket
import struct
from status_codes import StatusCodes
from logger import init_logger
from client_encryption import encrypt_with_server_public_key

logger = init_logger('client.manager')


def request_registration_token(server_host, server_port, user_id, version):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_host, server_port))
        logger.info(f"Connected to server at {server_host}:{server_port}")

        # Request token
        op = StatusCodes.REQUEST_REGISTRATION_TOKEN.value
        header_format = 'I B B H'
        header_data = struct.pack(header_format, user_id, version, op, 0)  # payload_len = 0
        client_socket.send(header_data)

        # Receive response
        response_header_format = 'B H H'
        response_header_size = struct.calcsize(response_header_format)
        response_header_data = client_socket.recv(response_header_size)
        response_version, response_status, payload_len = struct.unpack(response_header_format, response_header_data)

        if response_status == StatusCodes.TOKEN_ISSUED.value:
            payload = client_socket.recv(payload_len)
            token = payload[:6].decode()  # Extract token
            server_public_key = payload[6:].decode()  # Extract public key
            logger.info(f"Token: {token}, Public Key: {server_public_key}")
            return token, server_public_key

        logger.error(f"Failed to receive token. Status: {response_status}")
        return None, None

    except Exception as e:
        logger.error(f"Error in request_registration_token: {e}")
        return None, None
    finally:
        client_socket.close()
        logger.info("Client socket closed.")


def register_user_request_with_token(server_host, server_port, user_id, client_public_key, token, server_public_key):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_host, server_port))
        logger.info(f"Connected to server at {server_host}:{server_port}")

        # Encrypt user ID and public key with the server's public key
        data_to_encrypt = f"{user_id}|{client_public_key}"
        encrypted_data = encrypt_with_server_public_key(data_to_encrypt, server_public_key)
        logger.info(f"Encrypted data length: {len(encrypted_data)}")

        # Pack and send the token and encrypted payload
        op = StatusCodes.REQUEST_SECURE_REGISTRATION_COMPLETE.value
        encrypted_len = len(encrypted_data)
        token_encoded = token.encode()

        header_format = '>I B B H 6s'  # Ensure consistent endianness
        header_data = struct.pack(header_format, user_id, 1, op, encrypted_len, token_encoded)

        logger.info(f"Header data length: {len(header_data)}")
        logger.info(f"Sending header: {header_data}")
        client_socket.send(header_data)

        logger.info(f"Sending encrypted data: {encrypted_data}")
        client_socket.send(encrypted_data)
        logger.info("Token and encrypted data sent.")

        # Receive response
        response_header_format = '>B H'  # Match the server's response format
        response_header_size = struct.calcsize(response_header_format)
        response_header_data = client_socket.recv(response_header_size)

        logger.info(f"Response header received: {response_header_data}")
        response_version, response_status = struct.unpack(response_header_format, response_header_data)

        if response_status == StatusCodes.REQUEST_REGISTRATION_COMPLETE.value:
            logger.info("User registration completed successfully.")
        else:
            logger.error(f"Registration failed. Server returned status: {response_status}")

    except Exception as e:
        logger.error(f"Error in register_user_request_with_token: {e}")
    finally:
        client_socket.close()
        logger.info("Client socket closed.")



def register_request(server_host, server_port, user_id, version, client_public_key):
    try:
        # Step 1: Request the registration token and server public key
        token, server_public_key = request_registration_token(server_host, server_port, user_id, version)
        if not token or not server_public_key:
            logger.error("Failed to obtain registration token or server public key. Exiting registration process.")
            return

        logger.info(f"Token received: {token}")
        logger.info(f"Server public key received: {server_public_key}")

        # Step 2: Use the token to complete registration
        register_user_request_with_token(server_host, server_port, user_id, client_public_key, token, server_public_key)

    except Exception as e:
        logger.error(f"Error in register_request: {e}")


