import struct
from logger import init_logger
from status_codes import StatusCodes
from message_manager import send_message, deliver_unsent_messages
from user_manager import request_registration_token, complete_registration


logger = init_logger('server.manager')


def handle_client_connection(client_socket, time_stamp):
    try:
        header_format = 'I B B H'
        header_size = struct.calcsize(header_format)
        header_data = client_socket.recv(header_size)
        if not header_data:
            raise ConnectionError("Failed to receive header data")

        user_id, version, op, message_len = struct.unpack(header_format, header_data)
        logger.info(f"Received request: user_id={user_id}, version={version}, op={op}, message_len={message_len}")

        if op == StatusCodes.REQUEST_SEND_MESSAGE.value:
            recipient_id = client_socket.recv(4)
            send_message(client_socket, message_len, version, user_id, struct.unpack('I', recipient_id)[0], time_stamp)
        elif op == StatusCodes.REQUEST_GET_UNSENT_MESSAGES.value:
            deliver_unsent_messages(client_socket, version, user_id)
        elif op == StatusCodes.REQUEST_REGISTRATION_TOKEN.value:
            request_registration_token(client_socket, version)
        elif op == StatusCodes.REQUEST_SECURE_REGISTRATION_COMPLETE.value:
            complete_registration(client_socket, version)
        else:
            response = struct.pack('B H', version, StatusCodes.SERVER_ERROR.value)
            client_socket.send(response)
            logger.error(f"Unknown operation: {op}")
    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        client_socket.close()
