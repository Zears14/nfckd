import nfc
import time

from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.exceptions import InvalidSignature
from loguru import logger
from .logger_config import configure_logger
from .exceptions import NFCkdError
from .utils import load_hmac_key
from .key_derivation import KeyDerivation
from .DerivedKey import DerivedKey


class NFCkd:
    """
    NFCkd handles NFC tag authentication and session key derivation.
    """

    def __init__(
        self,
        hmac_key_path: str = "hmac_key.pkey",
        device: str = "tty:USB0:pn532",
        log_level: str = "INFO"
    ) -> None:
        configure_logger(log_level)
        self.device = device
        logger.info(f"NFCkd initializing with device '{device}' and HMAC key path '{hmac_key_path}'")
        self.hmac_key = load_hmac_key(Path(hmac_key_path))
        self.derivation = KeyDerivation(self.hmac_key)
        logger.debug("KeyDerivation instance initialized")

    def _read_verified_seed(self) -> bytes:
        """
        Read and verify seed from NFC tag.
        :return: Seed bytes.
        :raises NFCkdError: On any read or verification error.
        """
        try:
            clf = nfc.ContactlessFrontend(self.device)
            logger.debug(f"Connecting to NFC device: {self.device}")
        except Exception as e:
            logger.critical(f"Failed to connect to NFC device: {e}")
            raise NFCkdError(f"Failed to connect to NFC device: {e}")
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

            except InvalidSignature:
                logger.error("HMAC verification failed")
                clf.close()
                raise NFCkdError("HMAC verification failed.")
            except Exception as e:
                logger.error(f"Error while processing tag: {e}")
                clf.close()
                raise NFCkdError(f"Read error: {e}")

        try:
            logger.info("Waiting for NFC tag...")
            clf.connect(rdwr={'on-connect': callback, 'beep-on-connect': False})
        except Exception as e:
            logger.error(f"NFC connection failed: {e}")
            raise NFCkdError(f"NFC connection failed: {e}")

        # clf already closed in callback
        if seed is None:
            logger.error("No seed retrieved from tag")
            raise NFCkdError("Failed to obtain verified seed.")

        logger.debug("Seed successfully verified and extracted")
        return seed

    def authenticate(self) -> DerivedKey:
        """
        Perform authentication and derive session key.
        :return: DerivedKey
        """
        logger.info("Starting authentication process...")
        seed = self._read_verified_seed()
        logger.debug("Deriving keys from verified seed")
        ikey = self.derivation.intermediate(seed)
        session_key = self.derivation.session(ikey)
        logger.info("Authentication completed successfully")
        return session_key