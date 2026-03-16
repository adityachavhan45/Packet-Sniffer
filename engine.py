from __future__ import annotations

import json
import os
import threading
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

from scapy.all import AsyncSniffer, ICMP, IP, TCP, UDP, rdpcap, sniff, wrpcap

from config import (
    DEFAULT_RECENT_ALERTS,
    DEFAULT_RECENT_EVENTS,
    LOG_FILE,
    PCAP_FILE,
    SUMMARY_FILE,
    SUSPICIOUS_PORTS,
    TIMELINE_BUCKETS,
)
from models import PacketEvent
from utils import capture_interfaces, default_summary, display_time, list_interfaces, now_iso, severity_weight


class LiveIDS:
    def __init__(
        self,
        pcap_file: Path = PCAP_FILE,
        log_file: Path = LOG_FILE,
        summary_file: Path = SUMMARY_FILE,
        recent_limit: int = DEFAULT_RECENT_EVENTS,
    ) -> None:
        self.pcap_file = Path(pcap_file)
        self.log_file = Path(log_file)
        self.summary_file = Path(summary_file)
        self.recent_limit = recent_limit
        self.lock = threading.Lock()
        self.reset_runtime()

    @staticmethod
    def _truncate(value: str, width: int) -> str:
        if len(value) <= width:
            return value.ljust(width)
        return value[: width - 1] + "."

    def _format_packet_row(
        self,
        *,
        packet_no: int,
        readable_time: str,
        source: str,
        destination: str,
        protocol: str,
        length: int,
        port: int | None,
        tcp_flags: str,
        severity: str,
        event_risk: int,
        note: str,
    ) -> str:
        info_parts: list[str] = []
        if port is not None:
            info_parts.append(f"Port {port}")
        if tcp_flags:
            info_parts.append(f"Flags {tcp_flags}")
        if note:
            info_parts.append(note)
        if not info_parts:
            info_parts.append("Normal traffic")

        info = " | ".join(info_parts)
        return (
            f"{str(packet_no).rjust(5)}  "
            f"{readable_time:<8}  "
            f"{self._truncate(source, 18)}  "
            f"{self._truncate(destination, 18)}  "
            f"{protocol:<6}  "
            f"{str(length).rjust(5)}  "
            f"{(tcp_flags or '-'):^7}  "
            f"{severity[:10]:<10}  "
            f"{str(event_risk).rjust(3)}  "
            f"{info}"
        )

    def _print_capture_banner(self, interfaces: list[str]) -> None:
        print(f"[*] LIVE IDS started on interface(s): {', '.join(interfaces)}")
        print("[*] Press CTRL+C to stop")
        print("[*] Terminal view: live packet feed\n")
        print(" No.   Time      Source              Destination         Proto     Len   Flags    Severity    Risk  Info")
        print("-" * 120)

    def reset_runtime(self) -> None:
        self.protocol_counts: Counter[str] = Counter({"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0})
        self.source_counts: Counter[str] = Counter()
        self.destination_counts: Counter[str] = Counter()
        self.port_counts: Counter[int] = Counter()
        self.conversation_counts: Counter[str] = Counter()
        self.flag_counts: Counter[str] = Counter()
        self.unique_ports_by_source: dict[str, set[int]] = defaultdict(set)
        self.unique_destinations_by_source: dict[str, set[str]] = defaultdict(set)
        self.risk_by_source: Counter[str] = Counter()
        self.total_bytes = 0
        self.total_packets = 0
        self.recent_events: deque[dict[str, Any]] = deque(maxlen=self.recent_limit)
        self.alerts: deque[dict[str, Any]] = deque(maxlen=DEFAULT_RECENT_ALERTS)
        self.timeline: deque[dict[str, Any]] = deque(maxlen=TIMELINE_BUCKETS)
        self.terminal_header = " No.   Time      Source              Destination         Proto     Len   Flags    Severity    Risk  Info"
        self.terminal_rows: deque[str] = deque(maxlen=40)
        self.status = "idle"
        self.started_at: str | None = None
        self.last_packet_at: str | None = None
        self.interface: str | None = None
        self.source_mode = "live"
        self.timeline_cursor = 0
        self.detection_state = {
            "port_sweep": set(),
            "host_sweep": set(),
            "burst": set(),
            "service_touch": set(),
        }

    def ensure_storage(self, truncate_logs: bool = False) -> None:
        self.pcap_file.touch(exist_ok=True)
        self.summary_file.write_text(json.dumps(default_summary(), indent=2), encoding="utf-8")
        if truncate_logs or not self.log_file.exists():
            self.log_file.write_text("", encoding="utf-8")

    def log_event(self, message: str) -> None:
        with self.log_file.open("a", encoding="utf-8") as handle:
            handle.write(message + "\n")

    def _record_alert(self, *, timestamp: str, source: str, severity: str, rule: str, message: str) -> None:
        alert = {
            "timestamp": timestamp,
            "source": source,
            "severity": severity,
            "rule": rule,
            "message": message,
        }
        self.alerts.appendleft(alert)
        self.risk_by_source[source] += severity_weight(severity)
        self.log_event(f"[{severity.upper()}] {rule}: {message}")

    def _protocol_for_packet(self, packet: Any) -> tuple[str, int | None, str]:
        if TCP in packet:
            return "TCP", int(packet[TCP].dport), str(packet[TCP].flags)
        if UDP in packet:
            return "UDP", int(packet[UDP].dport), ""
        if ICMP in packet:
            return "ICMP", None, ""
        return "OTHER", None, ""

    def _touch_timeline(self, protocol: str, length: int) -> None:
        if not self.timeline or self.timeline[-1]["index"] != self.timeline_cursor:
            self.timeline.append(
                {
                    "index": self.timeline_cursor,
                    "label": f"T{self.timeline_cursor + 1}",
                    "packets": 0,
                    "bytes": 0,
                    "tcp": 0,
                    "udp": 0,
                    "icmp": 0,
                    "other": 0,
                }
            )

        bucket = self.timeline[-1]
        bucket["packets"] += 1
        bucket["bytes"] += length
        bucket[protocol.lower()] += 1 if protocol.lower() in {"tcp", "udp", "icmp", "other"} else 0
        if self.total_packets and self.total_packets % 150 == 0:
            self.timeline_cursor += 1

    def _security_posture(self) -> dict[str, Any]:
        high_risk_sources = sum(1 for _, score in self.risk_by_source.items() if score >= 50)
        active_alerts = len(self.alerts)
        score = max(5, 100 - min(85, active_alerts * 8 + high_risk_sources * 10))
        if score >= 80:
            classification = "healthy"
        elif score >= 60:
            classification = "watch"
        elif score >= 40:
            classification = "elevated"
        else:
            classification = "critical"
        return {
            "score": score,
            "classification": classification,
            "high_risk_sources": high_risk_sources,
            "active_alerts": active_alerts,
        }

    def _detections_catalog(self) -> list[dict[str, Any]]:
        return [
            {
                "rule": "Port Sweep",
                "triggered": len(self.detection_state["port_sweep"]),
                "description": "Single source touching many destination ports.",
            },
            {
                "rule": "Host Sweep",
                "triggered": len(self.detection_state["host_sweep"]),
                "description": "Single source contacting many unique hosts.",
            },
            {
                "rule": "Traffic Burst",
                "triggered": len(self.detection_state["burst"]),
                "description": "Abnormally high packet volume from one source.",
            },
            {
                "rule": "Sensitive Service Touch",
                "triggered": len(self.detection_state["service_touch"]),
                "description": "Traffic observed toward ports commonly used by admin or data services.",
            },
        ]

    def _build_summary_locked(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "started_at": self.started_at,
            "last_packet_at": self.last_packet_at,
            "interface": self.interface,
            "source": self.source_mode,
            "packets_processed": self.total_packets,
            "total_bytes": self.total_bytes,
            "protocols": dict(self.protocol_counts),
            "top_sources": [{"label": ip, "count": count} for ip, count in self.source_counts.most_common(6)],
            "top_destinations": [{"label": ip, "count": count} for ip, count in self.destination_counts.most_common(6)],
            "top_ports": [{"label": str(port), "count": count} for port, count in self.port_counts.most_common(6)],
            "top_conversations": [
                {"label": flow, "count": count}
                for flow, count in self.conversation_counts.most_common(6)
            ],
            "threat_leaderboard": [
                {"label": source, "count": score}
                for source, score in self.risk_by_source.most_common(6)
            ],
            "timeline": list(self.timeline),
            "terminal_header": self.terminal_header,
            "terminal_rows": list(self.terminal_rows),
            "recent_events": list(self.recent_events),
            "alerts": list(self.alerts),
            "flag_counters": dict(self.flag_counts),
            "security_posture": self._security_posture(),
            "detections": self._detections_catalog(),
        }

    def _save_summary_locked(self) -> None:
        self.summary_file.write_text(json.dumps(self._build_summary_locked(), indent=2), encoding="utf-8")

    def summary(self) -> dict[str, Any]:
        with self.lock:
            return self._build_summary_locked()

    def _mark_capture_stopped(self) -> None:
        with self.lock:
            self.status = "stopped"
            self._save_summary_locked()

    def _apply_detections(
        self,
        *,
        timestamp: str,
        source: str,
        destination: str,
        protocol: str,
        port: int | None,
        length: int,
        tcp_flags: str,
    ) -> tuple[str, str, int]:
        severity = "normal"
        note_parts: list[str] = []
        event_risk = 0

        if port is not None:
            self.unique_ports_by_source[source].add(port)
        self.unique_destinations_by_source[source].add(destination)

        if protocol == "TCP" and port is not None and port in SUSPICIOUS_PORTS:
            key = (source, port)
            if key not in self.detection_state["service_touch"]:
                self.detection_state["service_touch"].add(key)
                self._record_alert(
                    timestamp=timestamp,
                    source=source,
                    severity="low",
                    rule="Sensitive Service Touch",
                    message=f"{source} contacted {SUSPICIOUS_PORTS[port]} on port {port}",
                )
            note_parts.append(f"service port {port} ({SUSPICIOUS_PORTS[port]})")
            event_risk += 12
            severity = "suspicious"

        if len(self.unique_ports_by_source[source]) >= 8 and source not in self.detection_state["port_sweep"]:
            self.detection_state["port_sweep"].add(source)
            self._record_alert(
                timestamp=timestamp,
                source=source,
                severity="high",
                rule="Port Sweep",
                message=f"{source} touched {len(self.unique_ports_by_source[source])} unique destination ports",
            )
            note_parts.append("multi-port sweep pattern")
            event_risk += 40
            severity = "alert"

        if len(self.unique_destinations_by_source[source]) >= 10 and source not in self.detection_state["host_sweep"]:
            self.detection_state["host_sweep"].add(source)
            self._record_alert(
                timestamp=timestamp,
                source=source,
                severity="medium",
                rule="Host Sweep",
                message=f"{source} contacted {len(self.unique_destinations_by_source[source])} unique destinations",
            )
            note_parts.append("host sweep behaviour")
            event_risk += 28
            severity = "alert"

        if self.source_counts[source] >= 120 and source not in self.detection_state["burst"]:
            self.detection_state["burst"].add(source)
            self._record_alert(
                timestamp=timestamp,
                source=source,
                severity="medium",
                rule="Traffic Burst",
                message=f"{source} generated more than 120 packets in the capture window",
            )
            note_parts.append("source burst volume")
            event_risk += 24
            severity = "alert"

        if protocol == "TCP" and "S" in tcp_flags and "A" not in tcp_flags:
            self.flag_counts["syn_only"] += 1
            event_risk += 4
        if protocol == "TCP" and "F" in tcp_flags:
            self.flag_counts["fin"] += 1
        if protocol == "TCP" and "R" in tcp_flags:
            self.flag_counts["rst"] += 1
            event_risk += 5

        if length >= 1200:
            note_parts.append("large payload")
            event_risk += 8
            if severity == "normal":
                severity = "suspicious"

        return severity, ", ".join(note_parts), min(100, event_risk)

    def _process_packet(
        self,
        packet: Any,
        *,
        persist_packet: bool,
        log_to_file: bool,
        emit_console: bool,
    ) -> None:
        if IP not in packet:
            return

        timestamp = now_iso()
        readable_time = display_time()
        source = str(packet[IP].src)
        destination = str(packet[IP].dst)
        protocol, port, tcp_flags = self._protocol_for_packet(packet)
        length = len(packet)
        flow = f"{source} -> {destination}"

        with self.lock:
            self.total_packets += 1
            self.total_bytes += length
            self.last_packet_at = timestamp
            self.protocol_counts[protocol] += 1
            self.source_counts[source] += 1
            self.destination_counts[destination] += 1
            self.conversation_counts[flow] += 1
            if port is not None:
                self.port_counts[port] += 1
            severity, note, event_risk = self._apply_detections(
                timestamp=timestamp,
                source=source,
                destination=destination,
                protocol=protocol,
                port=port,
                length=length,
                tcp_flags=tcp_flags,
            )
            self._touch_timeline(protocol, length)

            event = PacketEvent(
                timestamp=timestamp,
                source=source,
                destination=destination,
                protocol=protocol,
                port=port,
                length=length,
                risk=event_risk,
                flag=severity,
                note=note,
                tcp_flags=tcp_flags,
            ).to_dict()
            self.recent_events.appendleft(event)
            terminal_row = self._format_packet_row(
                packet_no=self.total_packets,
                readable_time=readable_time,
                source=source,
                destination=destination,
                protocol=protocol,
                length=length,
                port=port,
                tcp_flags=tcp_flags,
                severity=severity,
                event_risk=event_risk,
                note=note,
            )
            self.terminal_rows.appendleft(terminal_row)
            self._save_summary_locked()

        if emit_console:
            print(terminal_row)
        message = f"[{readable_time}] {source} -> {destination} | {protocol}"
        if port is not None:
            message += f" | DPORT: {port}"
        if tcp_flags:
            message += f" | FLAGS: {tcp_flags}"
        if note:
            message += f" | {note}"
        if log_to_file:
            self.log_event(message)
        if persist_packet:
            wrpcap(str(self.pcap_file), packet, append=True)

    def _packet_handler(self, packet: Any) -> None:
        self._process_packet(packet, persist_packet=True, log_to_file=True, emit_console=True)

    def load_from_pcap(self, path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
        pcap_path = Path(path) if path else self.pcap_file
        self.reset_runtime()
        self.ensure_storage()
        self.status = "ready"
        self.started_at = now_iso()
        self.source_mode = "pcap"
        self.interface = "offline-analysis"

        if not pcap_path.exists() or pcap_path.stat().st_size == 0:
            self._save_summary_locked()
            return self.summary()

        packets = rdpcap(str(pcap_path))
        for packet in packets:
            self._process_packet(packet, persist_packet=False, log_to_file=False, emit_console=False)

        return self.summary()

    def _start_multi_interface_capture(self, interfaces: list[str]) -> None:
        sniffers = [AsyncSniffer(iface=iface_id, prn=self._packet_handler, store=False) for iface_id in interfaces]
        for sniffer_instance in sniffers:
            sniffer_instance.start()
        try:
            for sniffer_instance in sniffers:
                sniffer_instance.join()
        except KeyboardInterrupt:
            for sniffer_instance in sniffers:
                sniffer_instance.stop()
            print("\n[*] Capture stopped by user.")
            self._mark_capture_stopped()

    def start_live_capture(self, iface: str | None = None) -> None:
        if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
            raise PermissionError("Please run the sniffer with elevated privileges (sudo).")

        if iface:
            interfaces = [iface]
        else:
            interfaces = [item["id"] for item in capture_interfaces()]

        if not interfaces:
            raise RuntimeError("No active network interface found.")

        self.reset_runtime()
        self.ensure_storage(truncate_logs=True)
        self.status = "capturing"
        self.started_at = now_iso()
        self.interface = ", ".join(interfaces)
        self.source_mode = "live"
        self._save_summary_locked()

        self._print_capture_banner(interfaces)
        if len(interfaces) == 1:
            try:
                sniff(iface=interfaces[0], prn=self._packet_handler, store=False)
            except KeyboardInterrupt:
                print("\n[*] Capture stopped by user.")
                self._mark_capture_stopped()
            return
        self._start_multi_interface_capture(interfaces)

    def available_interfaces(self) -> list[dict[str, str]]:
        details = capture_interfaces()
        if details:
            return details
        return [{"id": iface, "label": iface} for iface in list_interfaces()]


runtime = LiveIDS()
