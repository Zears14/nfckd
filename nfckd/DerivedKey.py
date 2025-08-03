from __future__ import annotations

import base64
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Optional

from loguru import logger


@dataclass
class DerivedKey:
    """
    A class representing a derived cryptographic key with metadata and utility methods.

    This class encapsulates a cryptographic key along with its derivation timestamp and
    provides various utility methods for key manipulation, including serialization in
    different formats, expiration checking, and secure memory wiping.

    Attributes:
        _key (bytes): The raw key material.
        _derived_time (datetime): Timestamp when the key was derived.
    """

    _key: bytes
    _derived_time: Final[datetime] = datetime.now()

    @property
    def key(self) -> bytes:
        """Get the raw key bytes.

        Returns:
            bytes: The raw cryptographic key material.
        """
        return self._key

    @property
    def derived_time(self) -> datetime:
        """Get the key derivation timestamp.

        Returns:
            datetime: The timestamp when this key was derived.
        """
        return self._derived_time

    @property
    def hex(self) -> str:
        """Get the key as a hexadecimal string.

        Returns:
            str: Hexadecimal representation of the key.
        """
        return self._key.hex()

    @property
    def b64(self) -> str:
        """Get the key as a base64-encoded string.

        Returns:
            str: Base64-encoded representation of the key.
        """
        return base64.b64encode(self._key).decode("ascii")

    def is_expired(self, ttl: Optional[timedelta]) -> bool:
        """Check if the key has expired based on its derivation time.

        Args:
            ttl (Optional[timedelta]): The time-to-live duration after which the key
                is considered expired. If None, the key never expires.

        Returns:
            bool: True if the key has expired, False otherwise.
        """
        if ttl is None:
            return False
        return datetime.now() >= self._derived_time + ttl

    def wipe(self) -> None:
        """Securely wipe the key material from memory.

        This method overwrites the key bytes with zeros to ensure the sensitive
        key material is not left in memory. This is a security measure to prevent
        key material from being recovered from memory dumps.
        """
        # Overwrite bytearray buffer
        buf = bytearray(len(self._key))
        for i in range(len(buf)):
            buf[i] = 0
        self._key = bytes(buf)
        logger.debug("Key material securely wiped")

    def __bytes__(self) -> bytes:
        """Convert the DerivedKey to bytes.

        Returns:
            bytes: The raw key material.
        """
        return self._key

    def __str__(self) -> str:
        """Get a string representation of the key.

        Returns:
            str: The hexadecimal representation of the key.
        """
        return self.hex

    def __repr__(self) -> str:
        """Get a detailed string representation of the DerivedKey.

        Returns:
            str: A string containing the key's hex value and derivation time.
        """
        return (
            f"<DerivedKey hex={self.hex} derived_time={self._derived_time.isoformat()}>"
        )

    def __eq__(self, other: object) -> bool:
        """Compare two DerivedKey instances in a timing-safe manner.

        Args:
            other (object): Another object to compare with.

        Returns:
            bool: True if the other object is a DerivedKey with the same key material,
                NotImplemented if the other object is not a DerivedKey.

        Note:
            Uses hmac.compare_digest for constant-time comparison to prevent
            timing attacks.
        """
        if not isinstance(other, DerivedKey):
            return NotImplemented
        return hmac.compare_digest(self._key, other._key)
