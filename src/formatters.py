import logging
from json import dumps


class JSONFormatter(logging.Formatter):
    """
    Custom log formatter that formats log records as JSON.
    """

    def format(self, record):
        log_data = {
            'timestamp': self.formatTime(record, self.datefmt),
            'level': record.levelname,
            'module': record.module,
            'message': record.getMessage(),
        }
        return dumps(log_data)