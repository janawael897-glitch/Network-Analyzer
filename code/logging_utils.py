"""
utils/logging_utils.py - PacketGuard Logging Setup
Call setup_logging() once at startup.
"""

import logging
import os
import sys

class _SklearnWarningFilter(logging.Filter):
    def filter(self, record):
        msg = record.getMessage()
        return not any(k in msg for k in (
            "X does not have valid feature names",
            "feature names",
            "n_features_in_",
        ))


def setup_logging(log_file: str = None, level=logging.INFO):
    """Configure root logger. Optionally write to `log_file`."""
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )

    # Suppress noisy sklearn feature-name warnings
    for name in ("sklearn", "root", ""):
        logging.getLogger(name).addFilter(_SklearnWarningFilter())

    # Suppress flask/werkzeug noise
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
