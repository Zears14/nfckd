# NFCkd (NFC Key Derivation)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Development Status](https://img.shields.io/badge/status-alpha-orange.svg)](https://pypi.python.org/pypi/nfckd)

A Python library for implementing secure authentication and key derivation using NFC tags. NFCkd provides a robust mechanism for generating, storing, and deriving cryptographic keys using physical NFC tags as secure elements.

## Features

- **Secure Key Generation**
  - Random seed generation using `os.urandom()`
  - Password-based seed derivation option
  - 32-byte seed and key lengths

- **NFC Tag Operations**
  - Automatic NDEF formatting
  - Capacity verification (requires 64+ bytes)
  - Tag-specific binding through UID inclusion

- **Cryptographic Security**
  - HMAC-SHA256 for tag authentication
  - HKDF-SHA256 for key derivation
  - Constant-time key comparisons
  - Secure memory wiping

- **Developer Experience**
  - Simple, intuitive API
  - Comprehensive logging
  - Detailed error messages
  - Type hints throughout

## Installation

```bash
pip install nfckd
```

## Requirements

- Python 3.7+
- cryptography >= 45.0.5
- nfcpy >= 1.0.4
- loguru >= 0.7.3

## Quick Start

### 1. Writing an NFC Tag

```python
from nfckd.tag_writer import TagWriter

# Initialize with your HMAC key file
writer = TagWriter(
    hmac_key_path="hmac_key.pkey",
    device="tty:USB0:pn532"
)

# Generate a random seed
seed = writer.generate_seed()

# Or derive from password
seed = writer.generate_seed(use_hash=True)

# Write to tag
writer.write_tag(seed)
```

### 2. Reading and Deriving Keys

```python
from nfckd.client import NFCkd
from datetime import timedelta

# Initialize the client
client = NFCkd(
    hmac_key_path="hmac_key.pkey",
    device="tty:USB0:pn532"
)

# Authenticate and get session key
session_key = client.authenticate()

# Use the derived key
print(f"Key (hex): {session_key.hex}")
print(f"Key (b64): {session_key.b64}")

# Optional: Check expiration
if session_key.is_expired(timedelta(hours=1)):
    print("Key has expired")

# Important: Wipe key when done
session_key.wipe()
```

## Security Details

### Tag Authentication

Each NFC tag stores:

- A 32-byte random or derived seed
- A 32-byte HMAC of (seed + tag UID)

The HMAC binds the seed to the specific tag, preventing cloning attacks.

### Key Derivation Process

1. **Intermediate Key**: HMAC-SHA256(seed)
2. **Session Key**: HKDF-SHA256(intermediate_key)

This two-step process provides:

- Cryptographic separation between stages
- Domain separation through HKDF info parameter
- Optional key derivation parameters

## Development

### Logging

Configure logging level when initializing:

```python
writer = TagWriter(log_level="DEBUG")  # For detailed output
client = NFCkd(log_level="ERROR")      # For errors only
```

Available levels: DEBUG, INFO, WARNING, ERROR, CRITICAL, SILENT

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](https://github.com/Zears14/nfckd/blob/main/LICENSE) file for details.

## Author

Created by Zears14

## Acknowledgments

- [nfcpy](https://github.com/nfcpy/nfcpy) for NFC communication
- [cryptography](https://github.com/pyca/cryptography) for cryptographic operations
- [loguru](https://github.com/Delgan/loguru) for logging functionality
