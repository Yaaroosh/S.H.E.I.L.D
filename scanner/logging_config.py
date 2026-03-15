import logging
from pathlib import Path


class _MaxLevelFilter(logging.Filter):
    def __init__(self, max_level: int):
        super().__init__()
        self.max_level = max_level

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno <= self.max_level


def setup_logging(log_dir: str = "logs") -> None:
    root_logger = logging.getLogger()
    if root_logger.handlers:
        return

    logs_path = Path(log_dir)
    logs_path.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    debug_handler = logging.FileHandler(logs_path / "debug.log", encoding="utf-8")
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(formatter)

    info_handler = logging.FileHandler(logs_path / "info.log", encoding="utf-8")
    info_handler.setLevel(logging.INFO)
    info_handler.addFilter(_MaxLevelFilter(logging.WARNING))
    info_handler.setFormatter(formatter)

    error_handler = logging.FileHandler(logs_path / "error.log", encoding="utf-8")
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)

    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(debug_handler)
    root_logger.addHandler(info_handler)
    root_logger.addHandler(error_handler)
