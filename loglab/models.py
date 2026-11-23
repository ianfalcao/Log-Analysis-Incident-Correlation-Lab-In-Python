"""Representação comum dos registros observados nos arquivos de log."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Literal


@dataclass(kw_only=True)
class Event:
    """Evento com referência ao arquivo e às linhas de origem (inclusivas, base 1)."""

    source: Literal["access", "auth", "firewall", "app"]
    event_type: str
    file: str
    line_start: int
    line_end: int
    raw_message: str
    raw_timestamp: str | None = None
    timestamp: datetime | None = None
    host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    status: int | str | None = None
    details: dict[str, str | int | bool | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.line_start < 1 or self.line_end < self.line_start:
            raise ValueError("Intervalo de linhas inválido.")
        if self.timestamp is not None:
            if self.timestamp.utcoffset() is None:
                raise ValueError("O timestamp normalizado precisa de um fuso horário.")
            self.timestamp = self.timestamp.astimezone(timezone.utc)

    def to_dict(self) -> dict:
        """Devolve uma cópia para json.dumps, com horário ISO 8601 em UTC."""
        data = asdict(self)
        if self.timestamp is not None:
            data["timestamp"] = self.timestamp.isoformat()
        return data
