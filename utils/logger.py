import logging
import json
import sys

# Define ANSI color codes
RESET = "\033[0m"
COLOR_CODES = {
    'DEBUG': "\033[37m",  # White
    'INFO': "\033[34m",  # Green
    'WARNING': "\033[33m",  # Yellow
    'ERROR': "\033[31m",  # Red
    'CRITICAL': "\033[35m"  # Magenta
}


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_message = {
            "time": self.formatTime(record, self.datefmt),
            "name": record.name,
            "level": record.levelname,
            "message": record.getMessage()
        }
        json_message = json.dumps(log_message)

        # Get the color based on the log level
        color = COLOR_CODES.get(record.levelname, RESET)

        # Wrap the JSON message with color codes
        colored_json = f"{color}{json_message}{RESET}"

        return colored_json


def init_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(JsonFormatter())
        logger.addHandler(stream_handler)

    return logger
