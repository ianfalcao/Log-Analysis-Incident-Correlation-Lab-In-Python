"""Registros da aplicação Java, incluindo exceções com stack trace multilinha."""

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from loglab.models import Event


HEADER = re.compile(
    r"(?P<stamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+"
    r"(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+\[(?P<thread>[^]]+)\]\s+"
    r"(?P<component>[^\s:]+):\s*(?P<message>.*)"
)
EXCEPTION = re.compile(
    r"(?:Caused by: |Suppressed: )?(?P<class>(?:[\w$]+\.)*[\w$]*(?:Exception|Error))(?::.*)?"
)
FRAME = re.compile(r"(?:at \S+\(.*\)|\.\.\. \d+ more)")


def parse_app_line(line: str, *, file: str, line_number: int) -> Event:
    """Interpreta um cabeçalho isolado. Para incluir a pilha, use parse_app."""
    event = Event(source="app", event_type="app_invalid", file=file,
                  line_start=line_number, line_end=line_number, raw_message=line)
    match = HEADER.fullmatch(line.rstrip("\r\n"))
    if not match:
        event.details["reason"] = "Cabeçalho de aplicação inválido ou continuação órfã."
        return event
    event.raw_timestamp = match["stamp"]
    try:
        datetime.strptime(match["stamp"], "%Y-%m-%d %H:%M:%S,%f")
    except ValueError:
        event.details["reason"] = "Data ou hora de aplicação inválida."
        return event
    event.event_type = "application_log"
    event.details.update(level=match["level"], thread=match["thread"],
                         component=match["component"], message=match["message"])
    if exception := EXCEPTION.fullmatch(match["message"]):
        event.details["exception"] = exception["class"]
    return event


def parse_app(lines: Iterable[str], *, file: str) -> Iterator[Event]:
    pending = None
    record_lines = []
    for number, line in enumerate(lines, 1):
        if pending is not None:
            content = line.strip()
            exception = EXCEPTION.fullmatch(content)
            if exception or FRAME.fullmatch(content):
                if exception:
                    pending.details.setdefault("exception", exception["class"])
                record_lines.append(line)
                pending.line_end = number
                continue
            pending.raw_message = "".join(record_lines)
            yield pending
            pending = None

        event = parse_app_line(line, file=file, line_number=number)
        if event.event_type == "app_invalid":
            yield event
        else:
            pending = event
            record_lines = [line]
    if pending is not None:
        pending.raw_message = "".join(record_lines)
        yield pending
