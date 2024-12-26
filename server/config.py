from typing import ClassVar
from typing import ClassVar, List, Dict, Any
from pydantic_settings import BaseSettings
from pydantic import ValidationError
from utils.logger import init_logger

logger = init_logger('server.app.config')


class Settings(BaseSettings):
    # server settings
    SERVER_HOST: str = '127.0.0.1'
    SERVER_PORT: int = 5000
    SERVER_URL: str = f'http://{SERVER_HOST}:{SERVER_PORT}'

    # request settings
    header_format: str = 'I B B H'

    # database settings
    DATABASE_PATH: str = 'storage.db'

    # Protocol settings
    HEADER_FORMAT: ClassVar[str] = '!I B B H'  # network byte order, user_id, version, op, payload_len
    RESPONSE_FORMAT: ClassVar[str] = '!B H H'  # network byte order, version, status, payload_len

    # connected clients
    connected_clients: List[Dict[str, Any]] = []


try:
    settings = Settings()
except ValidationError as e:
    logger.error("Configuration error:", e)
    import sys
    sys.exit(1)
