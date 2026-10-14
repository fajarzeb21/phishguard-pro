
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

import sqlite3
import json
from io import BytesIO
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)

from analyzers.url_analyzer import analyze_url
from analyzers.email_analyzer import analyze_email


app = Flask(__name__)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "http://localhost:5173",
                "http://127.0.0.1:5173",
            ]
        }
    },
)

DATABASE = "investigations.db"


# -----------------------------
# DATABASE CONNECTION
# -----------------------------
def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


# -----------------------------
# CREATE DATABASE TABLE
# -----------------------------
def initialize_database():
    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_type TEXT NOT NULL,
            target TEXT NOT NULL,
            risk_score INTEGER,
            risk_level TEXT,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


# -----------------------------
# SAVE INVESTIGATION
# -----------------------------
def save_investigation(analysis_type, target, result):
    connection = get_db_connection()

    risk_score = result.get("risk_score", 0)
    risk_level = result.get("risk_level", "Unknown")
    created_at = datetime.now(timezone.utc).isoformat()

    cursor = connection.execute("""
        INSERT INTO investigations (
            analysis_type,
            target,
            risk_score,
            risk_level,
            result_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        analysis_type,
        target,
        risk_score,
        risk_level,
        json.dumps(result),
        created_at,
    ))

    investigation_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return investigation_id


# -----------------------------
# HEALTH CHECK
# -----------------------------
@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "success": True,
        "message": "PhishGuard Pro backend is running.",
    })


# -----------------------------
# URL ANALYSIS
# -----------------------------
@app.route("/api/analyze-url", methods=["POST"])
def analyze_url_route():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    if not isinstance(url, str) or not url.strip():
        return jsonify({
            "success": False,
            "error": "Please enter a URL.",
        }), 400

    url = url.strip()

    try:
        result = analyze_url(url)

        if not result.get("success"):
            return jsonify(result), 400

        investigation_id = save_investigation(
            "URL",
            url,
            result,
        )

        result["investigation_id"] = investigation_id

        return jsonify(result)

    except Exception:
        app.logger.exception("URL analysis failed")

        return jsonify({
            "success": False,
            "error": "URL analysis failed. Please try again.",
        }), 500


# -----------------------------
# EMAIL ANALYSIS
# -----------------------------
@app.route("/api/analyze-email", methods=["POST"])
def analyze_email_route():
    data = request.get_json(silent=True) or {}
    email_text = data.get("email_text", "")

    if not isinstance(email_text, str) or not email_text.strip():
        return jsonify({
            "success": False,
            "error": "Please enter email content.",
        }), 400

    email_text = email_text.strip()

    if len(email_text) > 50000:
        return jsonify({
            "success": False,
            "error": "Email content must not exceed 50,000 characters.",
        }), 400

    try:
        result = analyze_email(email_text)

        if not result.get("success"):
            return jsonify(result), 400

        investigation_id = save_investigation(
            "Email",
            "Email text analysis",
            result,
        )

        result["investigation_id"] = investigation_id

        return jsonify(result)

    except Exception:
        app.logger.exception("Email analysis failed")

        return jsonify({
            "success": False,
            "error": "Email analysis failed. Please try again.",
        }), 500


# -----------------------------
# INVESTIGATION HISTORY
# -----------------------------
@app.route("/api/history", methods=["GET"])
def get_investigation_history():
    connection = get_db_connection()

    rows = connection.execute("""
        SELECT
            id,
            analysis_type,
            target,
            risk_score,
            risk_level,
            created_at
        FROM investigations
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    history = [dict(row) for row in rows]

    return jsonify({
        "success": True,
        "total": len(history),
        "investigations": history,
    })


# -----------------------------
# INVESTIGATION DETAILS
# -----------------------------
@app.route("/api/history/<int:investigation_id>", methods=["GET"])
def get_investigation_details(investigation_id):
    connection = get_db_connection()

    row = connection.execute("""
        SELECT *
        FROM investigations
        WHERE id = ?
    """, (investigation_id,)).fetchone()

    connection.close()

    if row is None:
        return jsonify({
            "success": False,
            "error": "Investigation not found.",
        }), 404

    investigation = dict(row)

    investigation["result"] = json.loads(
        investigation.pop("result_json")
    )

    return jsonify({
        "success": True,
        "investigation": investigation,
    })


# -----------------------------
# PDF REPORT GENERATOR
# -----------------------------
@app.route(
    "/api/reports/<int:investigation_id>/pdf",
    methods=["GET"],
)
def download_investigation_pdf(investigation_id):
    connection = get_db_connection()

    row = connection.execute("""
        SELECT *
        FROM investigations
        WHERE id = ?
    """, (investigation_id,)).fetchone()

    connection.close()

    if row is None:
        return jsonify({
            "success": False,
            "error": "Investigation not found.",
        }), 404

    record = dict(row)

    try:
        result = json.loads(record["result_json"])
    except (TypeError, ValueError):
        result = {}

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"PhishGuard Pro Investigation #{investigation_id}",
        author="PhishGuard Pro",
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=28,
        textColor=colors.HexColor("#123047"),
        alignment=TA_CENTER,
        spaceAfter=8,
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#087e95"),
        spaceBefore=12,
        spaceAfter=7,
    ))

    styles.add(ParagraphStyle(
        name="ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        spaceAfter=5,
        wordWrap="CJK",
    ))

    story = []

    story.append(
        Paragraph("PHISHGUARD PRO", styles["ReportTitle"])
    )

    story.append(
        Paragraph(
            "Phishing Investigation & Threat Analysis Report",
            styles["Heading3"],
        )
    )

    story.append(Spacer(1, 10))

    # Report metadata
    metadata = [
        ("Investigation ID", f"#{record['id']}"),
        ("Analysis Type", str(record.get("analysis_type") or "Unknown")),
        ("Date", str(record.get("created_at") or "Unknown")),
        ("Target", str(record.get("target") or "Not provided")),
    ]

    metadata_rows = [
        [
            Paragraph(f"<b>{escape(label)}</b>", styles["ReportBody"]),
            Paragraph(escape(value), styles["ReportBody"]),
        ]
        for label, value in metadata
    ]

    metadata_table = Table(
        metadata_rows,
        colWidths=[42 * mm, 125 * mm],
        repeatRows=0,
    )

    metadata_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eaf3f7")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d5e1e8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))

    story.append(metadata_table)
    story.append(Spacer(1, 14))

    # Risk assessment
    story.append(
        Paragraph("Risk Assessment", styles["SectionHeading"])
    )

    score = result.get("risk_score", record.get("risk_score", 0))

    try:
        score = max(0, min(100, int(score)))
    except (TypeError, ValueError):
        score = 0

    risk_level = str(
        result.get("risk_level")
        or record.get("risk_level")
        or "Unknown"
    )

    risk_colors = {
        "low": "#16805d",
        "medium": "#b7791f",
        "high": "#c0392b",
    }

    risk_color = risk_colors.get(
        risk_level.lower(),
        "#34495e",
    )

    risk_table = Table(
        [[
            Paragraph(
                f"<b>Risk Score</b><br/><font size='18'>{score}/100</font>",
                styles["ReportBody"],
            ),
            Paragraph(
                f"<b>Risk Level</b><br/>"
                f"<font color='{risk_color}' size='16'>"
                f"{escape(risk_level)}</font>",
                styles["ReportBody"],
            ),
        ]],
        colWidths=[83 * mm, 83 * mm],
    )

    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f6f9")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#cbd8e0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))

    story.append(risk_table)

    # Findings
    story.append(
        Paragraph("Detected Findings", styles["SectionHeading"])
    )

    findings = result.get("findings", [])

    if not isinstance(findings, list) or not findings:
        story.append(
            Paragraph(
                "No findings were recorded for this investigation.",
                styles["ReportBody"],
            )
        )
    else:
        for index, finding in enumerate(findings, start=1):
            if not isinstance(finding, dict):
                continue

            name = escape(str(finding.get("name", "Finding")))
            severity = escape(str(finding.get("severity", "Unknown")))
            points = escape(str(finding.get("points", 0)))
            evidence = escape(
                str(finding.get("evidence", "No evidence provided"))
            )
            recommendation = escape(
                str(
                    finding.get(
                        "recommendation",
                        "No recommendation provided",
                    )
                )
            )

            finding_content = [
                Paragraph(
                    f"<b>{index}. {name}</b> — Severity: {severity}",
                    styles["ReportBody"],
                ),
                Paragraph(
                    f"<b>Points:</b> {points}",
                    styles["ReportBody"],
                ),
                Paragraph(
                    f"<b>Evidence:</b> {evidence}",
                    styles["ReportBody"],
                ),
                Paragraph(
                    f"<b>Recommendation:</b> {recommendation}",
                    styles["ReportBody"],
                ),
                Spacer(1, 7),
            ]

            story.append(KeepTogether(finding_content))

    # General recommendations
    story.append(
        Paragraph(
            "General Security Recommendations",
            styles["SectionHeading"],
        )
    )

    recommendations = [
        "Verify suspicious links using a trusted source before opening them.",
        "Do not enter passwords or one-time codes on unverified websites.",
        "Use multi-factor authentication where available.",
        "Keep your browser, operating system, and security software updated.",
        "Treat unexpected attachments and urgent requests with caution.",
    ]

    for recommendation in recommendations:
        story.append(
            Paragraph(
                f"&bull; {escape(recommendation)}",
                styles["ReportBody"],
            )
        )

    # Disclaimer
    story.append(
        Paragraph("Important Disclaimer", styles["SectionHeading"])
    )

    disclaimer = result.get(
        "disclaimer",
        (
            "This report uses heuristic indicators. The score is not "
            "a verified probability of phishing. A low score does not "
            "prove that a URL or email is safe."
        ),
    )

    story.append(
        Paragraph(
            escape(str(disclaimer)),
            styles["ReportBody"],
        )
    )

    story.append(Spacer(1, 12))

    story.append(
        Paragraph(
            "Generated by PhishGuard Pro",
            styles["ReportBody"],
        )
    )

    document.build(story)

    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"phishguard-investigation-{investigation_id}.pdf",
    )


# -----------------------------
# START SERVER
# -----------------------------
initialize_database()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )


