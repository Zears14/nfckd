"""NFC-based secure authentication and key-derivation library.

This package provides tools for NFC tag-based authentication and secure key
derivation. It implements a two-step key derivation process using HMAC-SHA256
and HKDF-SHA256.

Main Components:
    TagWriter: For formatting NFC tags and writing authenticated seeds
    NFCkd: For tag authentication and session key derivation
    DerivedKey: Represents derived keys with utility methods
    KeyDerivation: Handles the key derivation process

Example:
    Writing a tag:
        >>> from nfckd import TagWriter
        >>> writer = TagWriter()
        >>> seed = writer.generate_seed()
        >>> writer.write_tag(seed)

    Reading and deriving keys:
        >>> from nfckd.client import NFCkd
        >>> client = NFCkd()
        >>> session_key = client.authenticate()
        >>> print(session_key.hex)
"""

__version__ = "v0.0.0.dev4"
