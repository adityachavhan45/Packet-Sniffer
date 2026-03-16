from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PCAP_FILE = BASE_DIR / "packets.pcap"
LOG_FILE = BASE_DIR / "logs.txt"
SUMMARY_FILE = BASE_DIR / "summary.json"

DEFAULT_RECENT_EVENTS = 60
DEFAULT_RECENT_ALERTS = 20
TIMELINE_BUCKETS = 12

SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Alt",
}
