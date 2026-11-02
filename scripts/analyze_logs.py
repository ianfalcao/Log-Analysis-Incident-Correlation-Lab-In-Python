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


def print_banner() -> None:
    print(f"{BLUE}{'=' * 52}{RESET}")
    print(f"{BLUE}      AUTOMAÇÃO DE ANÁLISE E CORRELAÇÃO DE LOGS     {RESET}")
    print(f"{BLUE}{'=' * 52}{RESET}\n")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analisa e correlaciona arquivos de log do laboratório."
    )
    parser.add_argument(
        "log_dir",
        nargs="?",
        help="Diretório que contém os arquivos de log (padrão: logs/).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    log_dir = select_log_directory(args.log_dir)

    print_banner()

    if not (log_dir / "access.log").is_file() and not (log_dir / "auth.log").is_file():
        print(f"{RED}[!] Erro: Nenhum arquivo de log foi encontrado em '{log_dir}'.{RESET}")
        print(
            f"{YELLOW}Dica: Mova os logs para a pasta 'logs/' ou execute o script "
            f"a partir do diretório principal.{RESET}"
        )
        return 1

    print(f"{GREEN}[+] Lendo arquivos de log a partir do diretório: '{log_dir}'{RESET}\n")
    print(f"{YELLOW}Parte 1 concluída: ambiente preparado para análise.{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
