from config import settings
from utils.logger import init_logger, log
from utils.sock import close_socket
from registration_requests import register_request, connection_request
from messages_requests import send_message, check_for_incoming_messages
from client_connection import ClientDetails

logger = init_logger('client.app')

if __name__ == "__main__":
    try:
        client_1 = ClientDetails("508624196")
        client_2 = ClientDetails("584464896")
        version = 1  # Protocol version

        # step 1: make a connection and register the clients
        # Client 1
        log(f"-------------------------- Step 1 --------------------------")
        socket_1 = connection_request(settings.SERVER_HOST, int(settings.SERVER_PORT), client_1, version)
        register_request(socket_1, client_1, version)
        close_socket(socket_1)
        # Client 2
        socket_2 = connection_request(settings.SERVER_HOST, int(settings.SERVER_PORT), client_2, version)
        register_request(socket_2, client_2, version)
        close_socket(socket_2)

        # step 2 - client 1 sends a message to client 2 while client 2 is not connected
        log(f"-------------------------- Step 2 --------------------------")
        socket_1 = connection_request(settings.SERVER_HOST, int(settings.SERVER_PORT), client_1, version)
        send_message(
            client_socket=socket_1,
            client=client_1,
            recipient_id=client_2.id,
            message="hello Client2 how are you?",
            version=version
        )
        send_message(
            client_socket=socket_1,
            client=client_1,
            recipient_id=client_2.id,
            message="Client2! are you there?",
            version=version
        )
        close_socket(socket_1)

        # step 3 - client 2 connects and receives the message
        log(f"-------------------------- Step 3 --------------------------")
        socket_2 = connection_request(settings.SERVER_HOST, int(settings.SERVER_PORT), client_2, version)
        close_socket(socket_2)

        # step 4 - client 1 sends a message to client 2 while client 2 is connected
        log(f"-------------------------- Step 4 --------------------------")
        socket_1 = connection_request(settings.SERVER_HOST, int(settings.SERVER_PORT), client_1, version)
        socket_2 = connection_request(settings.SERVER_HOST, int(settings.SERVER_PORT), client_2, version)
        send_message(
            client_socket=socket_1,
            client=client_1,
            recipient_id=client_2.id,
            message="hello Client2 how are you?",
            version=version
        )
        # # # Check if Client 2 received a message
        incoming_message = check_for_incoming_messages(socket_2, client_2)
        if isinstance(incoming_message, str):
            log(f"Client 2 received a message: {incoming_message}")
        elif incoming_message:
            log(f"Client 2 received binary data: {incoming_message}")
        else:
            log("No messages received on Client 2's socket.")

        close_socket(socket_1)
        close_socket(socket_2)
    except Exception as e:
        close_socket(socket_1)
        close_socket(socket_2)
        logger.error(f"Error in client main: {e}")
