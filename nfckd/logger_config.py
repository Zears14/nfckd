from loguru import logger


def configure_logger(level: str = "INFO") -> None:
    """
    Configure Loguru logger with the specified level.

    :param level: Log level (e.g., "DEBUG", "INFO", "WARNING", "ERROR", "SILENT").
    """
    logger.remove()  # Remove default handler
    lvl = level.upper()

    if lvl == "SILENT":
        # In silent mode, only log CRITICAL level messages and discard them
        logger.add(lambda msg: None, level="CRITICAL", colorize=True)
    else:
        # Normal logging mode with color output
        logger.add(lambda msg: print(msg, end=""), level=lvl, colorize=True)
