class NFCkdError(Exception):
    """Base exception class for all nfckd library errors.

    This exception is raised when operations in the nfckd library fail, including:
    - NFC device connection failures
    - Tag read/write errors
    - Authentication failures
    - Key derivation errors
    - Invalid configuration

    Attributes:
        args: Variable length argument list.
        kwargs: Arbitrary keyword arguments.
    """

    def __init__(self, *args, **kwargs):
        """Initialize the NFCkdError.

        Args:
            *args: Variable length argument list to pass to Exception.
            **kwargs: Arbitrary keyword arguments to pass to Exception.
        """
        super().__init__(*args, **kwargs)
