import struct
from utils.logger import init_logger
from utils.recv import recv_exact
from request_handler import send_response
from utils.status_codes import StatusCodes
from message_manager import send_message, deliver_unsent_messages
from user_manager import request_registration_token, complete_registration


logger = init_logger('server.manager')


def handle_client_connection(client_socket, time_stamp):
    try:
        # Read and validate the header
        header_format = '!I B B H'  # user_id, version, op, payload_len
        try:
            header_data = recv_exact(client_socket, struct.calcsize(header_format))
            user_id, version, op, message_len = struct.unpack(header_format, header_data)
            
            logger.info(f"Raw header bytes: {header_data.hex()}")
            logger.info(f"Received request: user_id={user_id}, version={version}, op={op}, message_len={message_len}")
            
            # Handle different operations
            if op == StatusCodes.REQUEST_SEND_MESSAGE.value:
                recipient_id = struct.unpack('!I', recv_exact(client_socket, 4))[0]
                send_message(client_socket, message_len, version, user_id, recipient_id, time_stamp)
                
            elif op == StatusCodes.REQUEST_GET_UNSENT_MESSAGES.value:
                deliver_unsent_messages(client_socket, version, user_id)
                
            elif op == StatusCodes.REQUEST_REGISTRATION_TOKEN.value:
                request_registration_token(client_socket, version)
                
            elif op == StatusCodes.REQUEST_SECURE_REGISTRATION_COMPLETE.value:
                complete_registration(client_socket, version, user_id, message_len)
                
            else:
                logger.error(f"Unknown operation: {op}")
                send_response(client_socket, version, StatusCodes.SERVER_ERROR.value)
                
        except (ValueError, struct.error) as e:
            logger.error(f"Invalid header received: {e}")
            send_response(client_socket, 1, StatusCodes.SERVER_ERROR.value)
            
    except Exception as e:
        logger.error(f"Connection handling error: {e}")
    finally:
        client_socket.close()
