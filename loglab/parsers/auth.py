"""Normaliza registros syslog de auth.log sem acessar arquivos."""

import re
from collections.abc import Iterable, Iterator
from datetime import date
from ipaddress import ip_address

from loglab.models import Event


MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
HEADER = re.compile(
    r"(?P<stamp>(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) "
    r"(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d) (?P<host>\S+) "
    r"(?P<process>[\w.-]+)(?:\[(?P<pid>\d+)\])?:[ \t]*(?P<body>.+)"
)
PEER = r"(?: from (?P<peer>\S+)(?: port (?P<port>\d+))?)?"
SSH_AUTH = re.compile(
    r"(?P<result>Accepted|Failed) (?P<method>\S+) for "
    r"(?:(?P<invalid>invalid) user |user )?(?P<user>\S+)" + PEER
    + r"(?: (?P<protocol>ssh\d+)(?:: .*)?)?"
)
INVALID_USER = re.compile(
    r"(?:Invalid user |input_userauth_request: invalid user )(?P<user>\S+)"
    + PEER + r"(?: \[preauth\])?"
)
SESSION = re.compile(
    r"pam_unix\((?P<service>[^:()]+):session\): session (?P<action>opened|closed) "
    r"for user (?P<user>[^\s(]+)(?:\(uid=\d+\))?(?: by (?P<actor>.+))?"
)


def _peer(event: Event, address: str | None, port: str | None) -> None:
    if address:
        try:
            event.src_ip = str(ip_address(address))
        except ValueError:
            event.details["remote_host"] = address
    if port is not None:
        if len(port) > 5 or int(port) > 65535:
            raise ValueError("Porta de origem inválida.")
        event.src_port = int(port)


def _ssh(event: Event, body: str) -> None:
    if match := SSH_AUTH.fullmatch(body):
        method = match["method"]
        event.status = "success" if match["result"] == "Accepted" else "failed"
        event.event_type = f"ssh_{method}_{event.status}"
        event.details["method"] = method
        if match["invalid"]:
            event.details["invalid_user"] = True
        event.user = match["user"]
        event.protocol = match["protocol"]
        _peer(event, match["peer"], match["port"])
    elif match := INVALID_USER.fullmatch(body):
        event.event_type = "ssh_invalid_user"
        event.user = match["user"]
        _peer(event, match["peer"], match["port"])
    elif match := re.fullmatch(r"error: PAM: Authentication failure for (\S+) from (\S+)", body):
        event.event_type = "pam_auth_failure"
        event.status = "failed"
        event.user = match[1]
        _peer(event, match[2], None)
    elif match := re.fullmatch(r"PAM (\d+) more authentication failures; (.*)", body):
        event.event_type = "pam_failure_summary"
        event.details["reported_failures"] = int(match[1])
        fields = dict(token.split("=", 1) for token in match[2].split() if "=" in token)
        event.user = fields.get("user") or None
        _peer(event, fields.get("rhost"), None)


def _sudo(event: Event, body: str) -> None:
    actor, separator, payload = body.partition(" : ")
    if not separator or not actor.strip():
        return
    # COMMAND é o último campo e seu conteúdo pode incluir ponto e vírgula.
    context, separator, command = payload.partition(" ; COMMAND=")
    if not separator:
        return
    event.event_type = "sudo_command"
    event.user = actor.strip()
    event.details["command"] = command
    for item in context.split(" ; "):
        key, _, value = item.partition("=")
        if key in {"TTY", "PWD", "USER"}:
            name = {"TTY": "tty", "PWD": "cwd", "USER": "target_user"}[key]
            event.details[name] = value


def parse_auth_line(line: str, *, file: str, line_number: int) -> Event:
    """Preserva uma linha, inclusive quando o formato é inválido ou desconhecido."""
    event = Event(source="auth", event_type="auth_unrecognized", file=file,
                  line_start=line_number, line_end=line_number, raw_message=line)
    header = HEADER.fullmatch(line.rstrip("\r\n"))
    if not header:
        event.event_type = "auth_invalid"
        event.details["reason"] = "Cabeçalho syslog inválido ou mensagem ausente."
        return event

    body = header["body"]
    process = header["process"]
    event.raw_timestamp = header["stamp"]
    event.host = header["host"]
    event.details["process"] = process
    try:
        # Ano bissexto apenas para validar mês/dia, sem atribuir ano ao evento.
        date(2000, MONTHS.index(header["month"]) + 1, int(header["day"]))
    except ValueError:
        event.event_type = "auth_invalid"
        event.details["reason"] = "Data syslog inválida."
        return event
    if header["pid"]:
        event.details["pid"] = int(header["pid"])

    if match := SESSION.fullmatch(body):
        event.event_type = f"session_{match['action']}"
        event.user = match["user"]
        event.details["service"] = match["service"]
        if match["actor"]:
            event.details["opened_by"] = match["actor"]
    elif process == "sshd":
        try:
            _ssh(event, body)
        except ValueError as error:
            event.event_type = "auth_invalid"
            event.details["reason"] = str(error)
    elif process == "sudo":
        _sudo(event, body)
    elif process == "login":
        if match := re.fullmatch(r"USER (\S+): Login successful\.", body):
            event.event_type = "login_success"
            event.user = match[1]
            event.status = "success"
        elif match := re.fullmatch(r"FAILED LOGIN \d+ FROM (\S+) FOR (\S+), Authentication failure", body):
            event.event_type = "login_failed"
            event.user = match[2]
            event.status = "failed"
            event.details["login_from"] = match[1]
    return event


def parse_auth(lines: Iterable[str], *, file: str) -> Iterator[Event]:
    """Produz um evento por linha. Os tipos auth_invalid e auth_unrecognized são contáveis."""
    for number, line in enumerate(lines, start=1):
        yield parse_auth_line(line, file=file, line_number=number)
