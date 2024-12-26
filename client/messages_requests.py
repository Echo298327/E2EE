import socket
import struct
from utils.status_codes import StatusCodes
from utils.logger import init_logger
from utils.recv import recv_exact
from client_encryption import encrypt_with_public_key, decrypt_message


logger = init_logger('client.messages_requests')


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

        if status == StatusCodes.MESSAGE_DELIVERED.value:
            logger.info("Handling message delivered response.")

        # Receive payload if any
        payload = b''
        if payload_len > 0:
            payload = recv_exact(client_socket, payload_len)

        return version, status, payload
    except Exception as e:
        logger.error(f"Error receiving response: {e}")
        raise


def request_recipient_public_key(client_socket, sender_id, recipient_id):
    """
    Request the server to send the public key of the recipient.
    """
    sender_id = int(sender_id)
    recipient_id = int(recipient_id)
    try:
        if not isinstance(sender_id, int) or not isinstance(recipient_id, int):
            raise ValueError("Both sender_id and recipient_id must be integers.")

        # Prepare header and payload
        op = StatusCodes.REQUEST_RECIPIENT_PUBLIC_KEY.value
        payload = struct.pack('!I', recipient_id)
        payload_len = len(payload)

        # Prepare header with sender_id, version, op, and payload length
        header_format = '!I B B H'
        header_data = struct.pack(header_format, sender_id, 1, op, payload_len)

        # Send header and payload
        client_socket.send(header_data)
        client_socket.send(payload)
        logger.info(f"Request sent - sender_id: {sender_id}, recipient_id: {recipient_id}, op: {op}, length: {payload_len}")

        # Receive response
        response_header_format = '!I B B H'
        response_header_size = struct.calcsize(response_header_format)
        response_header_data = recv_exact(client_socket, response_header_size)
        response_user_id, version, status, payload_len = struct.unpack(response_header_format, response_header_data)
        logger.info(f"Received response header: user_id={response_user_id}, version={version}, status={status}, payload_len={payload_len}")

        # Validate response status
        if status == StatusCodes.REQUEST_RECIPIENT_PUBLIC_KEY.value:
            recipient_public_key = recv_exact(client_socket, payload_len).decode()
            return recipient_public_key

        logger.error(f"Failed to get recipient public key. Status: {status}")
        return None

    except Exception as e:
        logger.error(f"Error in request_recipient_public_key: {e}")
        return None


def send_encrypted_message(client_socket, sender_id, recipient_id, encrypted_message, version):
    """
    Send an encrypted message to the recipient using the provided socket.

    Args:
        client_socket (socket): The client socket connection to the server.
        sender_id (int): The sender's user ID.
        recipient_id (int): The recipient's user ID.
        encrypted_message (bytes): The encrypted message content.
        version (int): Protocol version.

    Returns:
        bool: True if the message was successfully delivered or saved, False otherwise.
    """
    sender_id = int(sender_id)
    recipient_id = int(recipient_id)
    try:
        # Validate inputs
        if not isinstance(sender_id, int) or not isinstance(recipient_id, int):
            raise ValueError("Both sender_id and recipient_id must be integers.")
        if not isinstance(encrypted_message, bytes):
            raise ValueError("Encrypted message must be in bytes format.")

        # Prepare header and payload
        op = StatusCodes.REQUEST_SEND_MESSAGE.value
        recipient_id_bytes = struct.pack("!I", recipient_id)  # Encode recipient_id (4 bytes)
        payload = recipient_id_bytes + encrypted_message  # Combine recipient_id and encrypted message
        payload_len = len(payload)

        # Prepare header with sender_id, version, op, and payload length
        header_format = "!I B B H"
        header_data = struct.pack(header_format, sender_id, version, op, payload_len)

        # Send header and payload
        client_socket.send(header_data)
        logger.info(f"Header sent: sender_id={sender_id}, op={op}, length={payload_len}")
        client_socket.send(payload)
        logger.info(f"Payload sent: recipient_id={recipient_id}, encrypted_message_length={len(encrypted_message)}")

        # Ensure all data is sent before closing the write channel
        client_socket.shutdown(socket.SHUT_WR)

        # Receive response
        response_header_format = "!B H"
        response_header_size = struct.calcsize(response_header_format)
        response_header_data = recv_exact(client_socket, response_header_size)
        response_version, response_status = struct.unpack(response_header_format, response_header_data)
        logger.info(f"Received response header: version={response_version}, status={response_status}")

        # Handle response
        if response_status == StatusCodes.MESSAGE_SAVED.value:
            logger.info("Message saved successfully (recipient offline).")
            return True
        elif response_status == StatusCodes.MESSAGE_DELIVERED.value:
            logger.info("Message delivered successfully (recipient online).")
            return True

        logger.error(f"Failed to send message. Status: {response_status}")
        return False

    except Exception as e:
        logger.error(f"Error in send_encrypted_message: {e}")
        return False


def send_message(client_socket, sender_id, recipient_id, message, version):
    """
    Send a message to the recipient.
    """
    try:
        # 1 step, request the recipient's public key
        recipient_public_key = request_recipient_public_key(client_socket, sender_id, recipient_id)
        if not recipient_public_key:
            logger.error("Failed to get recipient public key.")
            raise ValueError("Failed to get recipient public key.")
        logger.info(f"Received recipient public key. {recipient_public_key[:30]}...")
        # 2 step, send the message encrypted with the recipient's public key
        encrypted_message = encrypt_with_public_key(message, recipient_public_key)
        logger.info(f"Message encrypted with recipient public key")
        # 3 step, send the encrypted message to the recipient
        response = send_encrypted_message(client_socket, sender_id, recipient_id, encrypted_message, version)

    except Exception as e:
        logger.error(f"Error in send_message: {e}")


def check_for_incoming_messages(client_socket, client):
    """
    Check for incoming messages on the open socket without blocking.

    Args:
        client_socket (socket): The client socket connection.
        client (object): The client object containing the private key for decryption.

    Returns:
        str: The decrypted message, or None if no message is available.
    """
    try:
        # Temporarily set the socket to non-blocking mode
        client_socket.setblocking(False)

        # Attempt to read the header
        header_format = '!I B B H'  # sender_id, version, status, message_len
        header_size = struct.calcsize(header_format)

        try:
            header_data = client_socket.recv(header_size)
            if not header_data or len(header_data) < header_size:
                logger.debug("No complete header received.")
                return None

            sender_id, version, status, message_len = struct.unpack(header_format, header_data)
            logger.info(f"Header received: sender_id={sender_id}, version={version}, status={status}, message_len={message_len}")

            # Read the payload (message)
            if message_len > 0:
                payload = client_socket.recv(message_len)
                if len(payload) != message_len:
                    logger.error(f"Payload size mismatch. Expected {message_len} bytes, got {len(payload)} bytes.")
                    return None

                # Attempt to decode or decrypt the payload
                if status == StatusCodes.MESSAGE_DELIVERED.value:
                    try:
                        decrypted_message = decrypt_message(payload, client.private_key)
                        logger.info(f"Message decrypted successfully: {decrypted_message}")
                        return decrypted_message
                    except Exception as e:
                        logger.error(f"Failed to decrypt the message: {e}")
                        return None

                logger.warning("Received message with unknown status.")
                return None

        except BlockingIOError:
            # No data available, normal behavior for non-blocking sockets
            logger.debug("No incoming messages on the socket.")
            return None
        except Exception as e:
            logger.error(f"Error while checking for incoming messages: {e}")
            return None
    finally:
        # Restore the socket to blocking mode
        client_socket.setblocking(True)



