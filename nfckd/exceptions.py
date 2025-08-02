class NFCkdError(Exception):
    """Base exception for nfckd errors."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)