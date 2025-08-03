import getpass
import hashlib
import os
import time
from pathlib import Path
from typing import Final, Any

import ndef
import nfc
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from loguru import logger

from .exceptions import NFCkdError
from .logger_config import configure_logger
from .utils import load_hmac_key


class TagWriter:
    """A class for formatting and writing authenticated data to NFC tags.

    This class handles NFC tag operations including:
    - Formatting tags to NDEF format
    - Generating or deriving seed values
    - Creating authenticated records using HMAC
    - Writing combined seed and HMAC data to tags

    The written data format is: HMAC(seed + UID) || seed
    This binds the seed to the specific tag through its UID.

    Attributes:
        device (str): The NFC device path (e.g., 'tty:USB0:pn532')
        hmac_key (bytes): The 32-byte HMAC key for authentication
    """

    device: Final[str]
    hmac_key: Final[bytes]
    tag_capacity_min: Final[int]
    _clf: nfc.ContactlessFrontend

    def __init__(
        self,
        hmac_key_path: str = "hmac_key.pkey",
        device: str = "tty:USB0:pn532",
        log_level: str = "INFO",
        tag_capacity_min: int = 64,
    ) -> None:
        """Initialize the TagWriter with an NFC device and HMAC key.

        Args:
            hmac_key_path (str, optional): Path to the 32-byte HMAC key file.
                Defaults to "hmac_key.pkey".
            device (str, optional): NFC device identifier path.
                Defaults to "tty:USB0:pn532".
            log_level (str, optional): Logging verbosity level.
                Defaults to "INFO".
            tag_capacity_min (int, optional): Minimum required tag capacity in bytes.
                Defaults to 64.

        Raises:
            NFCkdError: If the HMAC key file cannot be loaded or is invalid.
        """
        configure_logger(log_level)
        self.device = device
        self.tag_capacity_min = tag_capacity_min
        logger.info(f"TagWriter initializing with device '{device}'")

        try:
            self.hmac_key = load_hmac_key(Path(hmac_key_path))
            logger.debug(f"HMAC key loaded from {hmac_key_path}")
        except Exception as e:
            logger.error(f"Failed to load HMAC key: {e}")
            raise NFCkdError(e) from e

    def generate_seed(self, use_hash: bool = False) -> bytes:
        """Generate or derive a 32-byte seed value.

        This method either generates a cryptographically secure random seed
        or derives one from a user-provided password using SHA-256.

        Args:
            use_hash (bool, optional): If True, prompt for a password and derive
                the seed using SHA-256. If False, generate a random seed using
                os.urandom. Defaults to False.

        Returns:
            bytes: A 32-byte seed value.
        """
        if use_hash:
            pwd = getpass.getpass("Enter password to derive seed: ").encode("utf-8")
            logger.info("Deriving seed from password")
            seed = hashlib.sha256(b"nfckd-seed" + pwd).digest()
            return seed
        else:
            logger.info("Generating random seed")
            return os.urandom(32)

    def write_tag(self, seed: bytes) -> None:
        """Write an authenticated seed to an NFC tag.

        This method performs the following operations:
        1. Connects to an NFC tag
        2. Formats the tag for NDEF if needed
        3. Verifies tag capacity (needs >= 64 bytes)
        4. Calculates HMAC over seed + tag UID
        5. Writes HMAC + seed as an NDEF record

        The written NDEF record contains:
        - First 32 bytes: HMAC-SHA256(seed + tag.identifier)
        - Last 32 bytes: seed

        Args:
            seed (bytes): The 32-byte seed to write to the tag.

        Raises:
            NFCkdError: If tag connection fails, formatting fails,
                capacity is insufficient, or writing fails.
        """
        self._clf = nfc.ContactlessFrontend(self.device)
        logger.info("Waiting for NFC tag...")
        try:

            def on_connect(tag: Any) -> bool:
                logger.info(f"Tag detected (UID: {tag.identifier.hex()}")
                start = time.monotonic()

                # format if needed
                if not tag.ndef:
                    if tag.format():
                        logger.info("Tag formatted to NDEF")
                    else:
                        raise NFCkdError("Cannot format tag to NDEF")

                if tag.ndef.capacity < self.tag_capacity_min:
                    raise NFCkdError(
                        (
                            f"Tag capacity insufficient: {tag.ndef.capacity} bytes "
                            f"(need {self.tag_capacity_min})"
                        )
                    )

                # Create and write NDEF record
                h = HMAC(self.hmac_key, hashes.SHA256())
                h.update(seed + tag.identifier)
                payload = h.finalize() + seed
                record = ndef.Record("application/octet-stream", "nfckd", payload)

                logger.debug(f"Writing NDEF record ({len(payload)} bytes)")
                tag.ndef.records = [record]

                duration = time.monotonic() - start
                logger.info(f"Tag written successfully in {duration:.2f}s")
                self._clf.close()
                return False

            self._clf.connect(rdwr={"on-connect": on_connect, "beep-on-connect": False})
        except Exception as e:
            logger.error(f"Tag write failed: {e}")
            raise NFCkdError(e) from e
        finally:
            if self._clf:
                self._clf.close()
                logger.debug("NFC device closed")
