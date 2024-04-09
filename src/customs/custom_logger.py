import logging


CRITICAL = 50
ERROR = 40
WARNING = 30
INFO = 20
DEBUG = 10
NOTSET = 0


class CustomLogger:
    """
    Custom logger class for handling both console and file logging.

    :param log_file: Path to the log file.
    :param console_level: Logging level for console output (default INFO).
    :param file_level: Logging level for file output (default ERROR).
    :param logger_name: Name of the logger (default "custom_logger").
    """

    def __init__(
        self,
        log_file: str,
        console_level: int = logging.INFO,
        file_level: int = logging.ERROR,
        logger_name: str = "custom_logger",
        file_size: int = 1024 * 1024,
        backup_count: int = 11,
    ) -> None:
        """
        Initialize the CustomLogger instance.

        :param log_file: Path to the log file.
        :param console_level: Logging level for console output (default INFO).
        :param file_level: Logging level for file output (default ERROR).
        :param logger_name: Name of the logger (default "custom_logger").
        """
        try:
            self.logger = logging.getLogger(logger_name)
            self.logger.setLevel(logging.INFO)

            # Log for console
            console_handler = logging.StreamHandler()
            console_handler.setLevel(console_level)
            console_formatter = logging.Formatter("%(message)s")
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
        except Exception as e:
            self.logger.error(
                f"Error during logger initialization: Failed to add console handler. Reason: {e}"
            )

        # Log for file
        try:
            file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
            file_handler.setLevel(file_level)
            file_formatter = logging.Formatter(
                "%(levelname)s, %(asctime)s %(module)s %(funcName)s %(lineno)d - %(message)s",
                "%Y-%m-%d %H:%M:%S",
            )

            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
        except Exception as e:
            self.logger.error(
                f"Error during logger initialization: Failed to add file handler. Reason: {e}!"
            )

    def log(self, message: str, level: int = logging.INFO) -> None:
        """
        Method for recording messages in the log.

        :param message: Message for writing to the log.
        :param level: Logging level (default Info).
        """
        try:
            self.logger.log(level, message)
        except Exception as e:
            self.logger.error(f"Error while logging to console: {e}")

    def set_format(
        self,
        format_str: str,
        level: int = logging.INFO,
        date_format: str = "%Y-%m-%d %H:%M:%S",
    ) -> None:
        """
        Method to set format for log messages for a specific logging level.

        :param format_str: Format string for log messages.
        :param level: Logging level for which to set the format (default INFO).
        :param date_format: Format string for date and time in log messages (default "%Y-%m-%d %H:%M:%S").
        """
        try:
            for handler in self.logger.handlers:
                if handler.level == level:
                    formatter = logging.Formatter(format_str, date_format)
                    handler.setFormatter(formatter)
        except Exception as e:
            self.logger.error(f"Error setting log format: {e}")


logger = CustomLogger("Error.log")


if __name__ == "__main__":
    logger.log("Hello this is custom logger!")
