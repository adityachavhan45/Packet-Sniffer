from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class PacketEvent:
    timestamp: str
    source: str
    destination: str
    protocol: str
    port: int | None
    length: int
    risk: int
    flag: str = "normal"
    note: str = ""
    tcp_flags: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "port": self.port,
            "length": self.length,
            "risk": self.risk,
            "flag": self.flag,
            "note": self.note,
            "tcp_flags": self.tcp_flags,
        }
