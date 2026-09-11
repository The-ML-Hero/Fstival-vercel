import logging
import re
import sys
from typing import Any
from app.core.config import settings

# Sensitive keyword patterns to mask in logs
SENSITIVE_PATTERNS = [
    (re.compile(r'(?i)("?(?:password|passwd|secret|api[_-]?key|token|auth(?:orization)?|bearer|access[_-]?token)"?\s*[:=]\s*["\'])([^"\']+)(["\'])'), r'\1[REDACTED]\3'),
    (re.compile(r'(?i)(Bearer\s+)([A-Za-z0-9\-\._~\+\/]+=*)'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(Basic\s+)([A-Za-z0-9\+\/]+=*)'), r'\1[REDACTED]'),
]


class SecretMaskingFormatter(logging.Formatter):
    """Custom logging formatter that scrubs passwords, tokens, and sensitive credentials."""

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        if not settings.MASK_SECRETS_IN_LOGS:
            return original

        redacted = original
        for pattern, repl in SENSITIVE_PATTERNS:
            redacted = pattern.sub(repl, redacted)
        return redacted


def setup_logger(name: str = "api_guardian") -> logging.Logger:
    """Configures and returns the application logger."""
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logger_instance = logging.getLogger(name)
    logger_instance.setLevel(log_level)

    if not logger_instance.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(log_level)
        formatter = SecretMaskingFormatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s:%(module)s:%(lineno)d] - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger_instance.addHandler(handler)

    return logger_instance


logger = setup_logger()
