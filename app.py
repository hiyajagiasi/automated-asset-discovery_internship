from __future__ import annotations

import os
from pathlib import Path
from threading import Lock, Thread
from typing import Any
from uuid import uuid4

from flask import Flask, jsonify, render_template, request, send_file

from modules.recon_service import ReconnaissanceService

app = Flask(__name__)
ACTIVE_SCANS: dict[str, dict[str, Any]] = {}
ACTIVE_SCANS_LOCK = Lock()
PLACEHOLDER_TARGETS = {"", "enter a url or domain"}


def _normalize_target(value: str | None) -> str:
    return (value or "").strip()


def _is_placeholder_target(value: str | None) -> bool:
    normalized = _normalize_target(value).lower()
    return normalized in PLACEHOLDER_TARGETS


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/scan")
def scan_target():
    target = _normalize_target(request.form.get("target"))
    if not target or _is_placeholder_target(target):
        return render_template("index.html", error="Please paste a target URL or domain."), 400

    scan_id = uuid4().hex
    with ACTIVE_SCANS_LOCK:
        ACTIVE_SCANS[scan_id] = {
            "target": target,
            "events": [],
            "complete": False,
            "error": None,
            "html_report": None,
            "excel_report": None,
        }

    def run_scan_in_thread() -> None:
        try:
            base_dir = Path(__file__).resolve().parent
            service = ReconnaissanceService(base_dir=base_dir, target=target)

            def progress(event: dict[str, Any]) -> None:
                with ACTIVE_SCANS_LOCK:
                    status = ACTIVE_SCANS.get(scan_id)
                    if status is not None:
                        status["events"].append(event)

            result = service.run(progress_callback=progress)
            with ACTIVE_SCANS_LOCK:
                status = ACTIVE_SCANS.get(scan_id)
                if status is not None:
                    status["complete"] = True
                    status["html_report"] = "/download/report.html"
                    status["excel_report"] = "/download/report.xlsx"
                    status["events"].append({
                        "phase": "complete",
                        "message": "Report ready",
                    })
        except Exception as exc:  # pragma: no cover - UI safety
            with ACTIVE_SCANS_LOCK:
                status = ACTIVE_SCANS.get(scan_id)
                if status is not None:
                    status["complete"] = True
                    status["error"] = str(exc)
                    status["events"].append({
                        "phase": "error",
                        "message": str(exc),
                    })

    thread = Thread(target=run_scan_in_thread, daemon=True)
    thread.start()

    return render_template("index.html", target=target, scan_started=True, scan_id=scan_id)


@app.get("/scan-status/<scan_id>")
def get_scan_status(scan_id: str):
    with ACTIVE_SCANS_LOCK:
        status = ACTIVE_SCANS.get(scan_id)
        if status is None:
            return jsonify({"error": "unknown scan"}), 404

        html_report = "/download/report.html" if status.get("html_report") else None
        excel_report = "/download/report.xlsx" if status.get("excel_report") else None

        return jsonify({
            "target": status["target"],
            "complete": status["complete"],
            "error": status["error"],
            "events": status["events"],
            "html_report": html_report,
            "excel_report": excel_report,
        })


@app.get("/download/report.html")
def download_report():
    report_path = Path(__file__).resolve().parent / "reports" / "report.html"
    if not report_path.exists():
        return "No report generated yet.", 404

    return send_file(
        report_path,
        mimetype="text/html",
        as_attachment=True,
        download_name="report.html",
    )


@app.get("/download/report.xlsx")
def download_excel_report():
    report_path = Path(__file__).resolve().parent / "reports" / "report.xlsx"
    if not report_path.exists():
        return "No Excel report generated yet.", 404

    return send_file(
        report_path,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name="report.xlsx",
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
