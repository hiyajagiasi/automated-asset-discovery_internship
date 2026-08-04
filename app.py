from __future__ import annotations

import os
from pathlib import Path
from threading import Lock, Thread
from typing import Any
from uuid import uuid4

from flask import Flask, jsonify, redirect, render_template, request, send_file, url_for

from modules.recon_service import ReconnaissanceService, ScanCancelledError

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
    scan_id = request.args.get("scan_id")
    if scan_id:
        with ACTIVE_SCANS_LOCK:
            status = ACTIVE_SCANS.get(scan_id)
            if status is not None:
                return render_template("index.html", target=status["target"], scan_started=True, scan_id=scan_id)
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
            "cancel_requested": False,
            "cancelled": False,
            "html_report": None,
            "excel_report": None,
            "csv_report": None,
            "json_report": None,
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

            def cancel_check() -> bool:
                with ACTIVE_SCANS_LOCK:
                    status = ACTIVE_SCANS.get(scan_id)
                    return bool(status and status.get("cancel_requested"))

            service.run(progress_callback=progress, cancel_check=cancel_check)
            with ACTIVE_SCANS_LOCK:
                status = ACTIVE_SCANS.get(scan_id)
                if status is not None:
                    if status.get("cancel_requested"):
                        status["complete"] = True
                        status["cancelled"] = True
                        status["events"].append({
                            "phase": "cancelled",
                            "message": "Scan cancelled",
                        })
                    else:
                        status["complete"] = True
                        status["html_report"] = "/download/report.html"
                        status["excel_report"] = "/download/report.xlsx"
                        status["csv_report"] = "/download/report.csv"
                        status["json_report"] = "/download/report.json"
                        status["events"].append({
                            "phase": "complete",
                            "message": "Report ready",
                        })
        except ScanCancelledError:
            with ACTIVE_SCANS_LOCK:
                status = ACTIVE_SCANS.get(scan_id)
                if status is not None:
                    status["complete"] = True
                    status["cancelled"] = True
                    status["events"].append({
                        "phase": "cancelled",
                        "message": "Scan cancelled",
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

    return redirect(url_for("index", scan_id=scan_id))


@app.post("/cancel/<scan_id>")
def cancel_scan(scan_id: str):
    with ACTIVE_SCANS_LOCK:
        status = ACTIVE_SCANS.get(scan_id)
        if status is None:
            return jsonify({"error": "unknown scan"}), 404

        status["cancel_requested"] = True
        status["cancelled"] = True
        status["complete"] = True
        status["events"].append({
            "phase": "cancelled",
            "message": "Scan cancelled",
        })

        return jsonify({
            "cancelled": True,
            "complete": True,
            "message": "Scan cancelled",
        })


@app.get("/scan-status/<scan_id>")
def get_scan_status(scan_id: str):
    with ACTIVE_SCANS_LOCK:
        status = ACTIVE_SCANS.get(scan_id)
        if status is None:
            return jsonify({"error": "unknown scan"}), 404

        html_report = "/download/report.html" if status.get("html_report") or (Path(__file__).resolve().parent / "reports" / "report.html").exists() else None
        excel_report = "/download/report.xlsx" if status.get("excel_report") or (Path(__file__).resolve().parent / "reports" / "report.xlsx").exists() else None
        csv_report = "/download/report.csv" if status.get("csv_report") or (Path(__file__).resolve().parent / "reports" / "report.csv").exists() else None
        json_report = "/download/report.json" if status.get("json_report") or (Path(__file__).resolve().parent / "reports" / "report.json").exists() else None

        return jsonify({
            "target": status["target"],
            "complete": status["complete"],
            "cancelled": status.get("cancelled", False),
            "error": status["error"],
            "events": status["events"],
            "html_report": html_report,
            "excel_report": excel_report,
            "csv_report": csv_report,
            "json_report": json_report,
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


@app.get("/download/report.csv")
def download_csv_report():
    report_path = Path(__file__).resolve().parent / "reports" / "report.csv"
    if not report_path.exists():
        return "No CSV export generated yet.", 404

    return send_file(
        report_path,
        mimetype="text/csv",
        as_attachment=True,
        download_name="report.csv",
    )


@app.get("/download/report.json")
def download_json_report():
    report_path = Path(__file__).resolve().parent / "reports" / "report.json"
    if not report_path.exists():
        return "No JSON export generated yet.", 404

    return send_file(
        report_path,
        mimetype="application/json",
        as_attachment=True,
        download_name="report.json",
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
