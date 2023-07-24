from datetime import datetime
import logging
import os


def get_logger(
        name: str,
        log_path: str,
        level: int = logging.WARNING,
        formatter: str = '%(asctime)s [%(name)s] %(levelname)s - %(message)s') -> logging.Logger:

    logger = logging.getLogger(name)
    logger.setLevel(level)
    fh = logging.FileHandler(
        os.path.join(log_path, "{}-{}.log").format(
            name,
            datetime.now().isoformat('T', 'seconds').replace(':', '-')
        )
    )
    fh.setLevel(level)
    fh.setFormatter(logging.Formatter(formatter))
    logger.addHandler(fh)

    return logger
