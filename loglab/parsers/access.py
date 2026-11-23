"""Registros HTTP no formato common/combined do laboratório."""

import re
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from ipaddress import ip_address

from loglab.models import Event


RECORD = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<stamp>[^]]+)\] '
    r'"(?P<request>(?:\\.|[^"\\])*)" (?P<status>[1-5][0-9]{2}|-) (?P<size>[0-9]+|-)'
    r'(?: "(?:\\.|[^"\\])*"(?: "(?P<agent>(?:\\.|[^"\\])*)")?)?'
)
REQUEST = re.compile(r'(?P<method>\S+) (?P<path>\S+)(?: (?P<protocol>HTTP/\d+(?:\.\d+)?))?')


def parse_access_line(line: str, *, file: str, line_number: int) -> Event:
    event = Event(source="access", event_type="access_invalid", file=file,
                  line_start=line_number, line_end=line_number, raw_message=line)
    match = RECORD.fullmatch(line.rstrip("\r\n"))
    if not match:
        event.details["reason"] = "Estrutura do registro HTTP inválida."
        return event

    event.raw_timestamp = match["stamp"]
    request = REQUEST.fullmatch(match["request"])
    if not request:
        event.details["reason"] = "Requisição HTTP inválida."
        return event
    try:
        event.src_ip = str(ip_address(match["ip"]))
        timestamp = datetime.strptime(match["stamp"], "%d/%b/%Y:%H:%M:%S %z")
        event.timestamp = timestamp.astimezone(timezone.utc)
        if match["size"] != "-":
            event.details["response_bytes"] = int(match["size"])
    except (ValueError, OverflowError) as error:
        event.details["reason"] = str(error)
        return event

    event.event_type = "http_request"
    event.details.update(method=request["method"], path=request["path"])
    event.protocol = request["protocol"]
    if match["status"] != "-":
        event.status = int(match["status"])
    if match["user"] != "-":
        event.user = match["user"]
    if match["agent"] not in (None, "-"):
        event.details["user_agent"] = match["agent"]
    return event


def parse_access(lines: Iterable[str], *, file: str) -> Iterator[Event]:
    for number, line in enumerate(lines, 1):
        yield parse_access_line(line, file=file, line_number=number)
