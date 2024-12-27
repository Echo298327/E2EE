import struct
from utils.logger import init_logger
from utils.recv import recv_exact
from request_handler import send_response
from utils.status_codes import StatusCodes
from message_manager import send_message, deliver_unsent_messages, get_recipient_public_key
from user_manager import request_registration_token, complete_registration
from db_manager import user_exists
from config import settings


logger = init_logger('server.manager')


def handle_client_connection(client_socket, time_stamp):
    user_id = None  # Initialize user_id for proper cleanup
    try:
        while True:  # Keep handling requests until the client closes the connection
            try:
                # Read and validate the header
                header_format = '!I B B H'  # user_id, version, op, payload_len
                header_data = recv_exact(client_socket, struct.calcsize(header_format))
                if not header_data:
                    break  # Exit the loop when no data is received

                # Unpack the header
                user_id, version, op, message_len = struct.unpack(header_format, header_data)
                logger.info(f"Received request: user_id={user_id}, version={version}, op={op}, message_len={message_len}")
                if not user_exists(user_id):
                    if op not in settings.allow_operations_for_unregistered_users:
                        logger.error(f"User {user_id} is unauthorized to perform operation {op}")
                        send_response(client_socket, version, StatusCodes.UNAUTHORIZED.value)
                        break
                # Add user to connected clients
                add_user_to_connected_clients(user_id, client_socket)

                # Handle different operations
                if op == StatusCodes.REQUEST_CONNECTION.value:
                    deliver_unsent_messages(client_socket, version, user_id)
                elif op == StatusCodes.REQUEST_REGISTRATION_TOKEN.value:
                    request_registration_token(client_socket, user_id, version)
                elif op == StatusCodes.REQUEST_SECURE_REGISTRATION_COMPLETE.value:
                    complete_registration(client_socket, version, user_id, message_len)
                elif op == StatusCodes.REQUEST_SEND_MESSAGE.value:
                    send_message(client_socket, message_len, version, user_id, time_stamp)
                elif op == StatusCodes.REQUEST_RECIPIENT_PUBLIC_KEY.value:
                    get_recipient_public_key(client_socket, version, user_id)
                else:
                    logger.error(f"Unknown operation: {op}")
                    send_response(client_socket, version, StatusCodes.SERVER_ERROR.value)

            except (ConnectionError, struct.error) as e:
                logger.info(f"Client disconnected or error occurred: {e}")
                break  # Exit the loop on client disconnection
            except ConnectionResetError as e:
                logger.info(f"Connection reset by client: {e}")
                break  # Handle connection reset gracefully
    except Exception as e:
        logger.error(f"Unexpected error while handling client connection: {e}")
    finally:
        if user_id:
            remove_disconnected_client(user_id)
        logger.warning(f"Closing client {user_id} connection.")
        client_socket.close()


def add_user_to_connected_clients(user_id, client_socket):
    """
    Add a user to the connected_clients list or update their connection if already exists.
    """
    client_exists = False
    for client in settings.connected_clients:
        if client['user_id'] == user_id:
            client['connection'] = client_socket
            client_exists = True
            break
    if not client_exists:
        settings.connected_clients.append({"user_id": user_id, "connection": client_socket})
        logger.warning(f"Connected Clients: {[client['user_id'] for client in settings.connected_clients]}")


def remove_disconnected_client(user_id):
    """
    Remove the client with the specified user_id from connected_clients.
    """
    settings.connected_clients = [client for client in settings.connected_clients if client["user_id"] != user_id]

