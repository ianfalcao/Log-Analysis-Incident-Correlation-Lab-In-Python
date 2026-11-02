#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

BLUE = "\033[0;34m"
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
RESET = "\033[0m"


def select_log_directory(directory: str | None) -> Path:
    """Seleciona o diretório de logs conforme a prioridade do Bash."""
    if directory and Path(directory).is_dir():
        return Path(directory)

    default_logs = Path("logs")
    if (default_logs / "access.log").is_file():
        return default_logs

    if Path("access.log").is_file():
        return Path(".")

    return default_logs


