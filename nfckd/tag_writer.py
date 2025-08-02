import getpass
import hashlib
import os
import time
from pathlib import Path

import ndef
import nfc
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from loguru import logger

from .exceptions import NFCkdError
from .logger_config import configure_logger
from .utils import load_hmac_key


class TagWriter:
    """
    TagWriter formats an NFC NTAG for NDEF and writes an authenticated seed + HMAC record.
    """

    def __init__(
        self,
        hmac_key_path: str = "hmac_key.pkey",
        device: str = "tty:USB0:pn532",
        log_level: str = "INFO",
    ) -> None:
        configure_logger(log_level)
        self.device = device
        logger.info(f"TagWriter initializing with device '{device}'")

        try:
            self.hmac_key = load_hmac_key(Path(hmac_key_path))
            logger.debug(f"HMAC key loaded from {hmac_key_path}")
        except Exception as e:
            logger.error(f"Failed to load HMAC key: {e}")
            raise NFCkdError(e)

    def generate_seed(self, use_hash: bool = False) -> bytes:
        """
        Generate or derive a 32-byte seed.
        If use_hash=True, prompts for password and hashes it.
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
        """
        Connect to the NFC device, format (if needed), and write NDEF record.
        Data = HMAC(seed + UID) + seed
        """
        clf = nfc.ContactlessFrontend(self.device)
        logger.info("Waiting for NFC tag...")
        try:

            def on_connect(tag):
                logger.info(f"Tag detected (UID: {tag.identifier.hex()})")
                start = time.monotonic()

                # format if needed
                if not tag.ndef:
                    if tag.format():
                        logger.info("Tag formatted to NDEF")
                    else:
                        raise NFCkdError("Cannot format tag to NDEF")

                if tag.ndef.capacity < 64:
                    raise NFCkdError(
                        f"Tag capacity insufficient: {tag.ndef.capacity} bytes (need 64)"
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
                clf.close()
                return False

            clf.connect(rdwr={"on-connect": on_connect, "beep-on-connect": False})
        except Exception as e:
            logger.error(f"Tag write failed: {e}")
            raise NFCkdError(e)
        finally:
            if clf:
                clf.close()
                logger.debug("NFC device closed")
