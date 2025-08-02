from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta
import hmac
import base64
from typing import Optional
from loguru import logger
@dataclass
class DerivedKey:
    """
    Represents a derived cryptographic key along with its derivation timestamp.

    Provides utility methods for serialization, expiration checks, and secure wiping.
    """
    _key: bytes
    _derived_time: datetime = datetime.now()

    @property
    def key(self) -> bytes:
        """Raw key bytes."""
        return self._key

    @property
    def derived_time(self) -> datetime:
        """Timestamp when key was derived."""
        return self._derived_time

    @property
    def hex(self) -> str:
        """Hexadecimal representation of the key."""
        return self._key.hex()

    @property
    def b64(self) -> str:
        """Base64-encoded representation of the key."""
        return base64.b64encode(self._key).decode('ascii')

    def is_expired(self, ttl: Optional[timedelta]) -> bool:
        """
        Check if the key is expired given a time-to-live duration.

        :param ttl: Time delta after which the key is considered expired.
        :return: True if expired, False otherwise.
        """
        if ttl is None:
            return False
        return datetime.now() >= self._derived_time + ttl

    def wipe(self) -> None:
        """
        Overwrite key material in memory with zeros.
        """
        # Overwrite bytearray buffer
        buf = bytearray(len(self._key))
        for i in range(len(buf)):
            buf[i] = 0
        self._key = bytes(buf)
        logger.debug("Key material securely wiped")

    def __bytes__(self) -> bytes:
        return self._key

    def __str__(self) -> str:
        return self.hex

    def __repr__(self) -> str:
        return f"<DerivedKey hex={self.hex} derived_time={self._derived_time.isoformat()}>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DerivedKey):
            return NotImplemented
        return hmac.compare_digest(self._key, other._key)