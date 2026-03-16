from __future__ import annotations

import os
import threading

from flask import Flask, jsonify, render_template, request, send_file

from config import PCAP_FILE
from engine import runtime

capture_thread: threading.Thread | None = None
capture_lock = threading.Lock()


def bootstrap_data() -> None:
    try:
        runtime.load_from_pcap(PCAP_FILE)
    except FileNotFoundError:
        runtime.ensure_storage()


def maybe_start_live_capture() -> None:
    if os.environ.get("LIVE_IDS_AUTOSTART", "0") != "1":
        return

    start_capture_thread(None)


def start_capture_thread(interface_id: str | None) -> dict[str, str]:
    global capture_thread
    with capture_lock:
        if capture_thread and capture_thread.is_alive():
            return {"ok": "false", "message": "Live capture is already running."}

        def runner() -> None:
            try:
                runtime.start_live_capture(iface=interface_id)
            except Exception as exc:  # pragma: no cover - surfaced to UI through status
                runtime.status = "error"
                runtime.log_event(f"[ERROR] {exc}")

        capture_thread = threading.Thread(target=runner, daemon=True)
        capture_thread.start()
        return {"ok": "true", "message": "Live capture started."}


def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def packets():
        return render_template("packets.html")

    @app.route("/analytics")
    def analytics():
        return render_template("analytics.html")

    @app.route("/api/summary")
    def summary():
        return jsonify(runtime.summary())

    @app.route("/api/interfaces")
    def interfaces():
        return jsonify({"items": runtime.available_interfaces()})

    @app.route("/api/capture/start", methods=["POST"])
    def capture_start():
        payload = request.get_json(silent=True) or {}
        interface_id = payload.get("interface")
        if interface_id == "auto":
            interface_id = None
        result = start_capture_thread(interface_id)
        return jsonify(result)

    @app.route("/api/health")
    def health():
        return jsonify({"ok": True, "status": runtime.summary().get("status", "idle")})

    @app.route("/api/export/summary")
    def export_summary():
        return send_file(runtime.summary_file, as_attachment=True, download_name="live_ids_summary.json")

    @app.route("/api/export/pcap")
    def export_pcap():
        return send_file(PCAP_FILE, as_attachment=True, download_name="live_ids_packets.pcap")

    bootstrap_data()
    maybe_start_live_capture()
    return app
