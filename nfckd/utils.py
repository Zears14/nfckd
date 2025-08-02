from pathlib import Path
from .exceptions import NFCkdError
from loguru import logger


def load_hmac_key(path: Path) -> bytes:
    """
    Load a 32-byte HMAC key from the given file path.

    :param path: Path to key file.
    :return: 32-byte key.
    :raises NFCkdError: If file not found or wrong length.
    """
    if not path.exists():
        logger.critical(f"HMAC key file not found: {path}")
        raise NFCkdError(f"HMAC key file not found: {path}")
        
    data = path.read_bytes()
    if len(data) != 32:
        logger.critical(f"Invalid HMAC key length: {len(data)} bytes (expected 32)")
        raise NFCkdError("HMAC key must be exactly 32 bytes")
        
    logger.debug(f"HMAC key loaded from {path}")
    return data