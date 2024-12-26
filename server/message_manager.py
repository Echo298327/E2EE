import struct
from utils.status_codes import StatusCodes
from server.db_manager import save_message, delete_unsent_messages, get_unsent_messages, get_user_public_key
from utils.logger import init_logger
from utils.recv import recv_exact
from config import settings

logger = init_logger('server.message_manager')


def deliver_unsent_messages(client_socket, version, user_id):
    """
    Send all unsent messages for a given user in a single response.
    """
    unsent_messages = get_unsent_messages(user_id)
    logger.info(f"Found {len(unsent_messages)} unsent messages for user_id={user_id}")

    if not unsent_messages:
        # Send a response indicating no unsent messages
        response = struct.pack('!B H H', version, StatusCodes.SUCCESSFUL_CONNECTION.value, 0)
        client_socket.sendall(response)
        logger.info(f"No unsent messages for user_id={user_id}")
        return

    # Prepare the aggregated payload
    payload = b""
    for message_id, sender_id, message_data in unsent_messages:
        message_len = len(message_data)
        # Each message includes: message_id, sender_id, message length, and message data
        payload += struct.pack('!I I H', message_id, sender_id, message_len) + message_data

    # Send the response header and aggregated payload
    payload_len = len(payload)
    response_header = struct.pack('!B H H', version, StatusCodes.MESSAGE_DELIVERED.value, payload_len)
    client_socket.sendall(response_header)
    client_socket.sendall(payload)
    logger.info(f"Delivered {len(unsent_messages)} unsent messages to user_id={user_id}")
    delete_unsent_messages(user_id)


def send_message(client_socket, message_len, version, sender_id, timestamp):
    """
    Handle the process of receiving a message from the client, attempting delivery,
    and saving it to the database if the recipient is not available.
    """
    try:
        # Receive recipient_id (4 bytes)
        recipient_id = struct.unpack('!I', recv_exact(client_socket, 4))[0]
        logger.info(f"Received recipient_id: {recipient_id} from sender_id: {sender_id}")

        # Adjust message_len to exclude recipient_id size
        adjusted_message_len = message_len - 4

        # Receive the encrypted message
        encrypted_message = recv_exact(client_socket, adjusted_message_len)
        logger.info(f"Received encrypted message of length: {len(encrypted_message)} bytes from sender_id={sender_id} to recipient_id={recipient_id}")

        # Check if the recipient is connected
        recipient_socket = get_recipient_socket(recipient_id)

        if recipient_socket:
            # Attempt to deliver the message directly
            deliver_message_to_recipient(recipient_socket, encrypted_message, sender_id, timestamp, version)
            logger.info(f"Message delivered successfully to recipient_id={recipient_id}")

            # Send a success response to the sender
            response = struct.pack('!B H', version, StatusCodes.MESSAGE_DELIVERED.value)
            client_socket.sendall(response)
        else:
            # Save the encrypted message to the database as binary
            save_message(recipient_id, sender_id, encrypted_message, timestamp)
            logger.info(f"Recipient_id={recipient_id} is offline. Message saved successfully.")

            # Send a success response indicating the message was saved
            response = struct.pack('!B H', version, StatusCodes.MESSAGE_SAVED.value)
            client_socket.sendall(response)

    except Exception as e:
        logger.error(f"Error in send_message: {e}")
        # Send an error response
        response = struct.pack('!B H', version, StatusCodes.SERVER_ERROR.value)
        client_socket.sendall(response)


def get_recipient_public_key(client_socket, version, user_id):
    """
    Fetch the public key of the requested recipient and send it back to the client.
    """
    try:
        # Receive the payload to extract recipient_id
        payload_len = struct.calcsize('!I')  # Recipient ID is 4 bytes
        recipient_id_data = recv_exact(client_socket, payload_len)
        recipient_id = struct.unpack('!I', recipient_id_data)[0]
        logger.info(f"Received recipient_id: {recipient_id} from user_id: {user_id}")

        # Fetch the recipient's public key from the database
        recipient_public_key = get_user_public_key(recipient_id)
        if not recipient_public_key:
            logger.error(f"Public key for recipient_id: {recipient_id} not found.")
            response = struct.pack('!I B B H', user_id, version, StatusCodes.SERVER_ERROR.value, 0)
            client_socket.sendall(response)
            return

        # Prepare the response
        payload = recipient_public_key.encode()
        payload_len = len(payload)
        response_header = struct.pack('!I B B H', user_id, version, StatusCodes.REQUEST_RECIPIENT_PUBLIC_KEY.value, payload_len)
        logger.info(f"Sending public key for recipient_id: {recipient_id}, payload_len: {payload_len}")

        # Send the response
        client_socket.sendall(response_header)
        client_socket.sendall(payload)
        logger.info(f"Public key sent successfully for recipient_id: {recipient_id}")

    except Exception as e:
        logger.error(f"Error in get_recipient_public_key: {e}")
        response = struct.pack('!I B B H', user_id, version, StatusCodes.SERVER_ERROR.value, 0)
        client_socket.sendall(response)


def get_recipient_socket(recipient_id):
    """
    Retrieve the socket for the recipient if they are connected.

    Args:
        recipient_id (str): The ID of the recipient.

    Returns:
        socket: The recipient's socket if connected, or None if not connected.
    """
    for client in settings.connected_clients:
        if client["user_id"] == recipient_id:
            return client["connection"]
    return None


def deliver_message_to_recipient(recipient_socket, message, sender_id, timestamp, version):
    """
    Deliver the message to the recipient directly.

    Args:
        recipient_socket: The recipient's socket connection.
        message: The message to deliver.
        sender_id: The ID of the sender.
        timestamp: The timestamp of the message.
        version: Protocol version.
    """
    try:
        # Prepare the header and payload for delivery
        message_len = len(message)
        header = struct.pack('!I B B H', sender_id, version, StatusCodes.MESSAGE_DELIVERED.value, message_len)

        # Send the header and payload to the recipient
        recipient_socket.sendall(header)
        recipient_socket.sendall(message)
        logger.info(f"Message delivered to recipient successfully.")
    except Exception as e:
        logger.error(f"Error delivering message to recipient: {e}")
        raise
