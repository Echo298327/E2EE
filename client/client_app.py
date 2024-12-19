from config import settings
from utils.logger import init_logger
from manager import register_request

logger = init_logger('client.app')


if __name__ == "__main__":
    try:
        user_id = 1234  # Unique identifier for the user
        version = 1     # Protocol version
        public_key = "SamplePublicKeyForUser"  # Replace with an actual public key
        register_request(settings.SERVER_HOST, int(settings.SERVER_PORT), user_id, version, public_key)
    except Exception as e:
        logger.error(f"Error in client main: {e}")
