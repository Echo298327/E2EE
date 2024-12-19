import struct
from utils.status_codes import StatusCodes
from server.db_manager import save_message, get_unsent_messages
from utils.logger import init_logger

logger = init_logger('server.message_manager')


def deliver_unsent_messages(client_socket, version, user_id):
    unsent_messages = get_unsent_messages(user_id)
    if not unsent_messages:
        response = struct.pack('B H', version, StatusCodes.NO_UNSENT_MESSAGES.value)
        logger.info(f"No unsent messages for user: {user_id}")
        client_socket.send(response)
        return


def send_message(client_socket, message_len, version, sender_id, recipient_id, timestamp):
    message = client_socket.recv(message_len).decode()
    save_message(recipient_id, sender_id, message, timestamp)
    response = struct.pack('B H', version, StatusCodes.MESSAGE_SAVED.value)
    logger.info(f"Unsent message saved for recipient: {recipient_id} at {timestamp}")
    client_socket.send(response)

