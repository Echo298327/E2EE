from pydantic_settings import BaseSettings
from pydantic import ValidationError
from logger import init_logger

logger = init_logger('server.app.config')


class Settings(BaseSettings):
    SERVER_HOST: str = '127.0.0.1'
    SERVER_PORT: int = 5000
    SERVER_URL: str = f'http://{SERVER_HOST}:{SERVER_PORT}'


try:
    settings = Settings()
except ValidationError as e:
    logger.error("Configuration error:", e)
    import sys
    sys.exit(1)
