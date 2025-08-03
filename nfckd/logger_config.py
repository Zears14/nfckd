from loguru import logger


def configure_logger(level: str = "INFO") -> None:
    """Configure the Loguru logger with custom settings and the specified level.

    This function sets up the Loguru logger with color output and custom formatting.
    In normal mode, messages are printed to stdout. In silent mode, only CRITICAL
    level messages are captured but discarded.

    Args:
        level (str, optional): The minimum log level to capture. Accepts standard
            log levels: "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", or
            "SILENT" for no output. Defaults to "INFO".

    Example:
        >>> configure_logger("DEBUG")  # Enable all logging
        >>> configure_logger("SILENT") # Disable all output
    """
    logger.remove()  # Remove default handler
    lvl = level.upper()

    if lvl == "SILENT":
        # In silent mode, only log CRITICAL level messages and discard them
        logger.add(lambda msg: None, level="CRITICAL", colorize=True)
    else:
        # Normal logging mode with color output
        logger.add(lambda msg: print(msg, end=""), level=lvl, colorize=True)
