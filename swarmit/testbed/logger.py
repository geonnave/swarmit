# SPDX-FileCopyrightText: 2022-present Inria
# SPDX-FileCopyrightText: 2022-present Alexandre Abadie <alexandre.abadie@inria.fr>
#
# SPDX-License-Identifier: BSD-3-Clause

"""Logger module."""

import logging
import logging.config
import os
from pathlib import Path

import structlog


def log_file_path() -> Path:
    """Persistent swarmit log file (override with SWARMIT_LOG_FILE)."""
    override = os.environ.get("SWARMIT_LOG_FILE")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".dotbot" / "logs" / "swarmit.log"


def setup_logging():
    """Setup logging.

    Logs go to stderr (rich, for the operator) and, when the log directory is
    writable, are also appended as parseable logfmt lines to
    ``log_file_path()`` so a flash run can be analysed after the fact.
    """
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ]

    structlog.configure(
        processors=processors,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    stdlib_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "logfmt": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processor": structlog.processors.LogfmtRenderer(
                    key_order=["timestamp", "level", "logger", "event"],
                    drop_missing=True,
                ),
            },
            "rich": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processor": structlog.dev.ConsoleRenderer(),
            },
        },
        "handlers": {
            # Console stays quiet at INFO so structured logs never clobber the
            # flash progress bar; the full INFO stream goes to the file handler
            # below. Warnings and errors still reach the operator.
            "console": {
                "formatter": "rich",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr",
                "level": "WARNING",
            }
        },
        "loggers": {
            "swarmit": {
                "handlers": ["console"],
                "level": logging.INFO,
                "propagate": True,
            },
        },
    }

    # Best-effort persistent file log (parseable logfmt); never let a
    # non-writable log dir break the CLI.
    try:
        path = log_file_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        stdlib_config["handlers"]["file"] = {
            "formatter": "logfmt",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": str(path),
            "maxBytes": 5_000_000,
            "backupCount": 3,
            "mode": "a",
        }
        stdlib_config["loggers"]["swarmit"]["handlers"].append("file")
    except OSError:
        pass

    logging.config.dictConfig(stdlib_config)


LOGGER = structlog.get_logger("swarmit")
