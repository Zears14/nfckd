import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from loguru import logger

from .DerivedKey import DerivedKey
from .exceptions import NFCkdError


class KeyDerivation:
    """
    Provides methods for deriving intermediate and session keys.
    """

    def __init__(self, hmac_key: bytes) -> None:
        self.hmac_key = hmac_key
        logger.debug(f"KeyDerivation initialized with {len(hmac_key)}-byte key")

    def intermediate(self, seed: bytes) -> bytes:
        """
        Derive an intermediate key using HMAC-SHA256.
        """
        logger.debug("Deriving intermediate key")
        start = time.monotonic()

        h = HMAC(self.hmac_key, hashes.SHA256())
        h.update(seed)
        intermediate_key = h.finalize()

        duration = time.monotonic() - start
        logger.debug(f"Intermediate key derived in {duration:.3f}s")
        return intermediate_key

    def session(
        self, intermediate_key: bytes, info: str = "nfc-auth-key-v1"
    ) -> DerivedKey:
        """
        Derive a session key using HKDF-SHA256.
        """
        logger.debug(f"Deriving session key with info: {info}")
        start = time.monotonic()
        try:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=info.encode("utf-8"),
            )
            key_bytes = hkdf.derive(intermediate_key)
            derived_key = DerivedKey(key_bytes)
            duration = time.monotonic() - start
            logger.info(f"Session key derived in {duration:.3f}s")
            return derived_key
        except Exception as e:
            logger.error(f"HKDF derivation failed: {e}")
            raise NFCkdError(f"HKDF derivation failed: {e}")
