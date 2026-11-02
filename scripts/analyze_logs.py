#!/usr/bin/env python3
"""Automação de análise e correlação de logs.

Partes implementadas:
1. Localização e validação do diretório de logs.
2. Cenário 1: rastreamento da sessão do usuário admin.
3. Cenário 2: correlação de erros HTTP 500 e exceções da aplicação.
4. Cenário 3: identificação de brute-force e reconhecimento.
5. Cenário 4: correlação de eventos associados a um IP suspeito.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Callable


BLUE = "\033[0;34m"
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
RESET = "\033[0m"

ADMIN_IP = "192.168.1.4"
ADMIN_USER = "admin"
BRUTE_FORCE_IP = "10.0.0.6"
SUSPICIOUS_IP = "10.0.0.5"


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


def print_header(title: str) -> None:
    print(f"{YELLOW}{'-' * 52}{RESET}")
    print(f"{YELLOW}{title}{RESET}")
    print(f"{YELLOW}{'-' * 52}{RESET}")


def matching_lines(log_file: Path, predicate: Callable[[str], bool]) -> list[str]:
    """Retorna linhas do arquivo que atendem ao critério informado."""
    return [
        line
        for line in log_file.read_text(encoding="utf-8", errors="replace").splitlines()
        if predicate(line)
    ]


def print_matches(lines: list[str], empty_message: str) -> None:
    print("\n".join(lines) if lines else empty_message)


def matching_lines_with_context(
    log_file: Path, text: str, context_lines: int
) -> list[str]:
    """Retorna cada ocorrência de texto e as linhas seguintes do log."""
    lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
    matches: list[str] = []

    for index, line in enumerate(lines):
        if text in line:
            matches.extend(lines[index : index + context_lines + 1])

    return matches


def analyze_admin_session(log_dir: Path) -> None:
    """Exibe eventos de autenticação e web associados à sessão de admin."""
    print_header(f"[Cenário 1] Sessão do Usuário Admin ({ADMIN_IP})")

    auth_log = log_dir / "auth.log"
    if auth_log.is_file():
        print(f"{GREEN}--> Registros de Autenticação (auth.log):{RESET}")
        print_matches(
            matching_lines(
                auth_log,
                lambda line: "Accepted" in line
                and (ADMIN_IP in line or ADMIN_USER in line),
            ),
            "Nenhum registro encontrado.",
        )

    access_log = log_dir / "access.log"
    if access_log.is_file():
        print(f"\n{GREEN}--> Registros do Web Server (access.log):{RESET}")
        print_matches(
            matching_lines(access_log, lambda line: ADMIN_IP in line),
            "Nenhum registro encontrado.",
        )

    print()


def analyze_internal_server_errors(log_dir: Path) -> None:
    """Correlaciona respostas HTTP 500 com o stack trace da aplicação."""
    print_header("[Cenário 2] Erros Internos no Servidor (HTTP 500)")

    access_log = log_dir / "access.log"
    if access_log.is_file():
        print(f"{GREEN}--> Requisições HTTP 500:{RESET}")
        print_matches(
            matching_lines(access_log, lambda line: '" 500 ' in line),
            "Nenhum registro encontrado.",
        )

    app_error_log = log_dir / "app_error.log"
    if app_error_log.is_file():
        print(f"\n{GREEN}--> Rastreamento do Stack Trace (app_error.log):{RESET}")
        print_matches(
            matching_lines_with_context(app_error_log, "NullPointerException", 8),
            "Nenhum registro encontrado.",
        )

    print()


def analyze_brute_force(log_dir: Path) -> None:
    """Exibe evidências de reconhecimento e brute-force do IP atacante."""
    print_header(f"[Cenário 3] Brute-Force e Reconhecimento ({BRUTE_FORCE_IP})")

    access_log = log_dir / "access.log"
    if access_log.is_file():
        print(f"{GREEN}--> Varredura Web:{RESET}")
        print_matches(
            matching_lines(access_log, lambda line: BRUTE_FORCE_IP in line),
            "Nenhum registro.",
        )

    auth_log = log_dir / "auth.log"
    if auth_log.is_file():
        print(f"\n{GREEN}--> Falhas de Autenticação SSH:{RESET}")
        auth_events = matching_lines(auth_log, lambda line: BRUTE_FORCE_IP in line)
        print_matches(auth_events, "Nenhum registro.")
        failed_passwords = sum("Failed password" in line for line in auth_events)
        print(f"Total de senhas incorretas: {RED}{failed_passwords}{RESET}")

    firewall_log = log_dir / "firewall.log"
    if firewall_log.is_file():
        print(f"\n{GREEN}--> Ações do Firewall:{RESET}")
        print_matches(
            matching_lines(firewall_log, lambda line: BRUTE_FORCE_IP in line),
            "Nenhum registro.",
        )

    print()


def analyze_suspicious_activity(log_dir: Path) -> None:
    """Correlaciona eventos associados ao IP suspeito nos logs disponíveis."""
    print_header(f"[Cenário 4] Atividade Suspeita ({SUSPICIOUS_IP})")

    log_sections = (
        ("access.log", "Registros do Web Server"),
        ("firewall.log", "Ações do Firewall"),
        ("auth.log", "Eventos de Autenticação SSH"),
    )
    for filename, title in log_sections:
        log_file = log_dir / filename
        if log_file.is_file():
            print(f"{GREEN}--> {title} ({filename}):{RESET}")
            print_matches(
                matching_lines(log_file, lambda line: SUSPICIOUS_IP in line),
                "Nenhum registro.",
            )
            print()


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
    analyze_admin_session(log_dir)
    analyze_internal_server_errors(log_dir)
    analyze_brute_force(log_dir)
    analyze_suspicious_activity(log_dir)
    print(f"{GREEN}[+] Análise concluída.{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
