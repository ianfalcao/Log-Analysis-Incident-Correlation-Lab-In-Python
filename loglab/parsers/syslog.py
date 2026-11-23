"""Cabeçalho syslog compartilhado pelos parsers Linux."""

import re
from datetime import date

from loglab.models import Event


MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
HEADER = re.compile(
    r"(?P<stamp>(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) "
    r"(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d) (?P<host>\S+) "
    r"(?P<process>[\w.-]+)(?:\[(?P<pid>\d+)\])?:[ \t]*(?P<body>.+)"
)


def read_header(event: Event) -> str | None:
    """Preenche os campos de origem e devolve o corpo, ou sinaliza um erro."""
    header = HEADER.fullmatch(event.raw_message.rstrip("\r\n"))
    if not header:
        event.event_type = f"{event.source}_invalid"
        event.details["reason"] = "Cabeçalho syslog inválido ou mensagem ausente."
        return None

    body = header["body"]
    process = header["process"]
    event.raw_timestamp = header["stamp"]
    event.host = header["host"]
    event.details["process"] = process
    try:
        # Ano bissexto apenas para validar mês/dia, sem atribuir ano ao evento.
        date(2000, MONTHS.index(header["month"]) + 1, int(header["day"]))
    except ValueError:
        event.event_type = f"{event.source}_invalid"
        event.details["reason"] = "Data syslog inválida."
        return None
    if header["pid"]:
        event.details["pid"] = int(header["pid"])

    return body
