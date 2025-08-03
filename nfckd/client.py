import time
from pathlib import Path

import nfc
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from loguru import logger

from .DerivedKey import DerivedKey
from .exceptions import NFCkdError
from .key_derivation import KeyDerivation
from .logger_config import configure_logger
from .utils import load_hmac_key


class NFCkd:
    """NFCkd handles NFC tag authentication and session key derivation.

    This class provides functionality to authenticate NFC tags and derive session keys
    using HMAC-SHA256 for tag verification and HKDF-SHA256 for key derivation.

    Attributes:
        device (str): The NFC device path to use (e.g., 'tty:USB0:pn532')
        hmac_key (bytes): The 32-byte HMAC key loaded from file
        derivation (KeyDerivation): Instance for handling key derivation operations
    """

    def __init__(
        self,
        hmac_key_path: str = "hmac_key.pkey",
        device: str = "tty:USB0:pn532",
        log_level: str = "INFO",
    ) -> None:
        """Initialize NFCkd with the specified device and HMAC key.

        Args:
            hmac_key_path (str, optional): Path to the HMAC key file.
                Defaults to "hmac_key.pkey".
            device (str, optional): NFC device identifier. Defaults to "tty:USB0:pn532".
            log_level (str, optional): Logging level to use. Defaults to "INFO".

        Raises:
            NFCkdError: If the HMAC key file cannot be loaded or is invalid.
        """
        configure_logger(log_level)
        self.device = device
        logger.info(
            f"NFCkd initializing with device '{device}' "
            f"and HMAC key path '{hmac_key_path}'"
        )
        self.hmac_key = load_hmac_key(Path(hmac_key_path))
        self.derivation = KeyDerivation(self.hmac_key)
        logger.debug("KeyDerivation instance initialized")

    def _read_verified_seed(self) -> bytes:
        """Read and verify seed from NFC tag.

        This method reads an NDEF record from an NFC tag, extracts the seed and MAC,
        and verifies the MAC using the stored HMAC key. The MAC is computed over
        the concatenation of the seed and tag UID to bind the seed to this specific tag.

        Returns:
            bytes: The verified 32-byte seed from the tag.

        Raises:
            NFCkdError: If the tag cannot be read, is missing NDEF records,
                has invalid format, or fails MAC verification.
        """
        try:
            clf = nfc.ContactlessFrontend(self.device)
            logger.debug(f"Connecting to NFC device: {self.device}")
        except Exception as e:
            logger.critical(f"Failed to connect to NFC device: {e}")
            raise NFCkdError(f"Failed to connect to NFC device: {e}") from e
        seed = None

        def callback(tag):
            nonlocal seed
            try:
                logger.info(f"Tag detected: {tag}")
                start = time.monotonic()
                if not tag.ndef or not tag.ndef.records:
                    logger.warning("Tag missing NDEF or records")
                    raise NFCkdError("No NDEF records found.")

                rec = tag.ndef.records[0]
                tag_mac = bytes(rec.data[:32])
                seed = bytes(rec.data[-32:])
                uid = tag.identifier

                logger.debug(f"Processing tag UID: {uid.hex()}")

                h = HMAC(self.hmac_key, hashes.SHA256())
                h.update(seed + uid)
                h.verify(tag_mac)
                duration = time.monotonic() - start

                logger.info("Tag authentication successful")
                logger.debug(f"Authentication completed in {duration:.2f} seconds")
                # close immediately and exit callback
                clf.close()
                return False  # tells connect() to return immediately

            except InvalidSignature as e:
                logger.error("HMAC verification failed")
                clf.close()
                raise NFCkdError("HMAC verification failed.") from e
            except Exception as e:
                logger.error(f"Error while processing tag: {e}")
                clf.close()
                raise NFCkdError(f"Read error: {e}") from e

        try:
            logger.info("Waiting for NFC tag...")
            clf.connect(rdwr={"on-connect": callback, "beep-on-connect": False})
        except Exception as e:
            logger.error(f"NFC connection failed: {e}")
            raise NFCkdError(f"NFC connection failed: {e}") from e

        # clf already closed in callback
        if seed is None:
            logger.error("No seed retrieved from tag")
            raise NFCkdError("Failed to obtain verified seed.")

        logger.debug("Seed successfully verified and extracted")
        return seed

    def authenticate(self) -> DerivedKey:
        """Perform NFC tag authentication and derive a session key.

        This method performs the complete authentication flow:
        1. Reads and verifies the seed from an NFC tag
        2. Derives an intermediate key using HMAC-SHA256
        3. Derives a final session key using HKDF-SHA256

        Returns:
            DerivedKey: A newly derived session key with timestamp.

        Raises:
            NFCkdError: If tag authentication or key derivation fails.
        """
        logger.info("Starting authentication process...")
        seed = self._read_verified_seed()
        logger.debug("Deriving keys from verified seed")
        ikey = self.derivation.intermediate(seed)
        session_key = self.derivation.session(ikey)
        logger.info("Authentication completed successfully")
        return session_key
