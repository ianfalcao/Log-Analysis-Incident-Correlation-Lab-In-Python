"""Registros UFW com campos chave=valor, com ou sem prefixo syslog."""

import re
from collections.abc import Iterable, Iterator
from ipaddress import ip_address

from loglab.models import Event
from loglab.parsers.syslog import read_header


UFW = re.compile(r"(?:\[\s*\d+(?:\.\d+)?\]\s+)?\[UFW (?P<action>[A-Z]+)\]\s+(?P<body>.+)")


def _port(value: str | None) -> int | None:
    if value is None:
        return None
    if not re.fullmatch(r"[0-9]{1,5}", value) or int(value) > 65535:
        raise ValueError(f"Porta inválida: {value}")
    return int(value)


def parse_firewall_line(line: str, *, file: str, line_number: int) -> Event:
    event = Event(source="firewall", event_type="firewall_invalid", file=file,
                  line_start=line_number, line_end=line_number, raw_message=line)
    body = line.rstrip("\r\n")
    if not body.startswith("["):
        body = read_header(event)
        if body is None:
            return event
    match = UFW.fullmatch(body)
    if not match:
        event.details["reason"] = "Registro UFW inválido ou ausente."
        return event
    fields = dict(token.split("=", 1) for token in match["body"].split() if "=" in token)
    if not fields.keys() & {"SRC", "DST", "IN", "OUT", "PROTO", "SPT", "DPT"}:
        event.details["reason"] = "Registro sem campos de rede reconhecidos."
        return event

    try:
        if "SRC" in fields:
            event.src_ip = str(ip_address(fields["SRC"]))
        if "DST" in fields:
            event.dst_ip = str(ip_address(fields["DST"]))
        event.src_port = _port(fields.get("SPT"))
        event.dst_port = _port(fields.get("DPT"))
    except ValueError as error:
        event.details["reason"] = str(error)
        return event
    event.event_type = "firewall_action"
    event.status = match["action"]
    event.protocol = fields.get("PROTO") or None
    event.details["in_interface"] = fields.get("IN") or None
    event.details["out_interface"] = fields.get("OUT") or None
    return event


def parse_firewall(lines: Iterable[str], *, file: str) -> Iterator[Event]:
    for number, line in enumerate(lines, 1):
        yield parse_firewall_line(line, file=file, line_number=number)
