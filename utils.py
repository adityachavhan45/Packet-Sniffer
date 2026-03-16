from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from scapy.all import get_if_list
from scapy.arch.windows import get_windows_if_list


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def display_time() -> str:
    return datetime.now().strftime("%H:%M:%S")


def get_active_interface() -> str | None:
    interfaces = get_if_list()
    for iface in interfaces:
        lowered = iface.lower()
        if lowered not in {"lo", "loopback"} and "loopback" not in lowered:
            return iface
    return None


def list_interfaces() -> list[str]:
    return list(get_if_list())


def _is_preferred_windows_adapter(name: str, description: str) -> bool:
    combined = f"{name} {description}".lower()
    blocked_terms = [
        "loopback",
        "wan miniport",
        "virtualbox host-only",
        "kernel debug",
        "wi-fi direct virtual adapter",
        "teredo",
        "6to4",
        "ip-https",
        "qos packet scheduler",
        "wfp ",
        "npcap packet driver",
        "native wifi filter",
        "virtual wifi filter",
    ]
    if any(term in combined for term in blocked_terms):
        return False

    preferred_terms = [
        "wi-fi",
        "wireless",
        "ethernet",
        "usb to ethernet",
        "remote ndis",
        "tap-windows",
    ]
    return any(term in combined for term in preferred_terms)


def capture_interfaces() -> list[dict[str, str]]:
    if os.name != "nt":
        return [{"id": iface, "label": iface} for iface in get_if_list() if "loopback" not in iface.lower()]

    npf_interfaces = set(get_if_list())
    results: list[dict[str, str]] = []
    seen: set[str] = set()

    for item in get_windows_if_list():
        name = str(item.get("name", "")).strip()
        description = str(item.get("description", "")).strip()
        guid = str(item.get("guid", "")).strip("{}")
        if not guid:
            continue
        iface_id = f"\\Device\\NPF_{{{guid}}}"
        if iface_id not in npf_interfaces:
            continue
        if not _is_preferred_windows_adapter(name, description):
            continue
        if iface_id in seen:
            continue
        seen.add(iface_id)
        label = f"{name} | {description}"
        results.append({"id": iface_id, "label": label})

    if results:
        return results

    fallback = []
    for iface in get_if_list():
        lowered = iface.lower()
        if lowered not in {"lo", "loopback"} and "loopback" not in lowered:
            fallback.append({"id": iface, "label": iface})
    return fallback


def severity_weight(severity: str) -> int:
    weights = {"low": 15, "medium": 30, "high": 50, "critical": 75}
    return weights.get(severity, 10)


def default_summary() -> dict[str, Any]:
    return {
        "status": "idle",
        "started_at": None,
        "last_packet_at": None,
        "interface": None,
        "source": "live",
        "packets_processed": 0,
        "total_bytes": 0,
        "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0},
        "alerts": [],
        "recent_events": [],
        "top_sources": [],
        "top_destinations": [],
        "top_ports": [],
        "top_conversations": [],
        "threat_leaderboard": [],
        "timeline": [],
        "terminal_header": "",
        "terminal_rows": [],
        "flag_counters": {},
        "security_posture": {
            "score": 100,
            "classification": "healthy",
            "high_risk_sources": 0,
            "active_alerts": 0,
        },
        "detections": [],
    }
