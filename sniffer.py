from __future__ import annotations

import argparse
import json

from engine import runtime


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LIVE IDS packet sniffer")
    parser.add_argument("--iface", help="Network interface to sniff on")
    parser.add_argument("--pcap", help="Analyze packets from an existing pcap file instead of live capture")
    parser.add_argument("--list-ifaces", action="store_true", help="List available network interfaces")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.list_ifaces:
        for index, iface in enumerate(runtime.available_interfaces(), start=1):
            print(f"{index}. {iface['label']}")
            print(f"   id: {iface['id']}")
        return
    if args.pcap:
        runtime.load_from_pcap(args.pcap)
        print(json.dumps(runtime.summary(), indent=2))
        return
    runtime.start_live_capture(iface=args.iface)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
