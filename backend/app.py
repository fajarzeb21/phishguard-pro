
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from pathlib import Path
from dotenv import load_dotenv

from analyzers.url_analyzer import analyze_url
from analyzers.email_analyzer import analyze_email
from analyzers.email_address_analyzer import analyze_email_address


# -----------------------------
# FLASK APPLICATION
# -----------------------------

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "http://localhost:5173",
                "http://127.0.0.1:5173",
                "https://phishguard-pro-two.vercel.app",
            ]
        }
    },
)


# -----------------------------
# ENVIRONMENT CONFIGURATION
# -----------------------------

ROOT_DIR = Path(__file__).resolve().parent.parent

load_dotenv(ROOT_DIR / ".env.local")
load_dotenv(Path(__file__).resolve().parent / ".env")


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

        if not isinstance(result, dict):
            app.logger.error("URL analyzer returned an invalid result.")
            return jsonify({
                "success": False,
                "error": "URL analysis returned an invalid response.",
            }), 500

        if not result.get("success"):
            return jsonify(result), 400

        # Return the result without saving it to public history.
        return jsonify(result)

    except Exception:
        app.logger.exception("URL analysis failed")

        return jsonify({
            "success": False,
            "error": "URL analysis failed. Please try again.",
        }), 500


# -----------------------------
# EMAIL CONTENT ANALYSIS
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

        if not isinstance(result, dict):
            app.logger.error(
                "Email content analyzer returned an invalid result."
            )
            return jsonify({
                "success": False,
                "error": "Email analysis returned an invalid response.",
            }), 500

        if not result.get("success"):
            return jsonify(result), 400

        # Return the result without saving submitted email content.
        return jsonify(result)

    except Exception:
        app.logger.exception("Email analysis failed")

        return jsonify({
            "success": False,
            "error": "Email analysis failed. Please try again.",
        }), 500


# -----------------------------
# EMAIL ADDRESS ANALYSIS
# -----------------------------

@app.route("/api/analyze-email-address", methods=["POST"])
def analyze_email_address_route():
    data = request.get_json(silent=True) or {}

    email = data.get("email", "")

    if not isinstance(email, str) or not email.strip():
        return jsonify({
            "success": False,
            "error": "Please enter an email address.",
        }), 400

    if len(email) > 254:
        return jsonify({
            "success": False,
            "error": "Email address is too long.",
        }), 400

    try:
        result = analyze_email_address(email)

        if not isinstance(result, dict):
            app.logger.error(
                "Email address analyzer returned an invalid result."
            )
            return jsonify({
                "success": False,
                "error": "Email address analysis returned an invalid response.",
            }), 500

        if not result.get("success"):
            return jsonify(result), 400

        # Do not save submitted email addresses.
        return jsonify(result)

    except Exception:
        app.logger.exception("Email address analysis failed")

        return jsonify({
            "success": False,
            "error": "Email address analysis failed. Please try again.",
        }), 500


# -----------------------------
# START SERVER
# -----------------------------

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )

