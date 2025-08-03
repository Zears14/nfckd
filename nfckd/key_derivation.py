import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from loguru import logger

from .DerivedKey import DerivedKey
from .exceptions import NFCkdError


class KeyDerivation:
    """A class that handles cryptographic key derivation operations.

    This class implements a two-step key derivation process:
    1. Derives an intermediate key using HMAC-SHA256
    2. Derives a final session key using HKDF-SHA256

    Attributes:
        hmac_key (bytes): A 32-byte key used for HMAC operations.
    """

    def __init__(self, hmac_key: bytes) -> None:
        """Initialize the KeyDerivation instance.

        Args:
            hmac_key (bytes): A 32-byte key used for HMAC operations in the
                intermediate key derivation step.
        """
        self.hmac_key = hmac_key
        logger.debug(f"KeyDerivation initialized with {len(hmac_key)}-byte key")

    def intermediate(self, seed: bytes) -> bytes:
        """Derive an intermediate key from a seed using HMAC-SHA256.

        This is the first step in the two-step key derivation process. It uses
        HMAC-SHA256 with the stored HMAC key to derive an intermediate key
        from the provided seed.

        Args:
            seed (bytes): The seed value to derive the intermediate key from,
                typically obtained from an NFC tag.

        Returns:
            bytes: A 32-byte intermediate key.
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
        """Derive a session key using HKDF-SHA256.

        This is the second step in the two-step key derivation process. It uses
        HKDF-SHA256 to derive a final session key from the intermediate key.
        The derived key is wrapped in a DerivedKey instance that provides
        additional utility methods and metadata.

        Args:
            intermediate_key (bytes): The intermediate key obtained from the first
                derivation step.
            info (str, optional): Context and application specific information
                string used in the HKDF calculation. Defaults to "nfc-auth-key-v1".

        Returns:
            DerivedKey: A newly derived session key wrapped in a DerivedKey instance.

        Raises:
            NFCkdError: If the HKDF key derivation fails.
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
