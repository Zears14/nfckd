from pathlib import Path

from loguru import logger

from .exceptions import NFCkdError


def load_hmac_key(path: Path) -> bytes:
    """Load and validate an HMAC key from a file.

    This function reads a 32-byte HMAC key from the specified file path.
    The key must be exactly 32 bytes long to be valid for use with
    HMAC-SHA256 operations.

    Args:
        path (Path): The filesystem path to the HMAC key file.

    Returns:
        bytes: The 32-byte HMAC key.

    Raises:
        NFCkdError: If the key file doesn't exist or the key length
            is not exactly 32 bytes.
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
