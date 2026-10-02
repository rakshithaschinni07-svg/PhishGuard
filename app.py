from flask import Flask, render_template, request, Response
import sqlite3
import re
from datetime import datetime
from urllib.parse import urlparse


app = Flask(__name__)


# =========================
# DATABASE CONNECTION
# =========================

def get_db_connection():
    connection = sqlite3.connect("phishguard.db")
    connection.row_factory = sqlite3.Row
    return connection


# =========================
# CREATE DATABASE TABLE
# =========================

def create_table():

    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            result TEXT NOT NULL,
            scanned_at TEXT,
            reasons TEXT
        )
    """)

    columns = connection.execute(
        "PRAGMA table_info(scans)"
    ).fetchall()

    column_names = [
        column["name"] for column in columns
    ]

    if "scanned_at" not in column_names:
        connection.execute(
            "ALTER TABLE scans ADD COLUMN scanned_at TEXT"
        )

    if "reasons" not in column_names:
        connection.execute(
            "ALTER TABLE scans ADD COLUMN reasons TEXT"
        )

    connection.commit()
    connection.close()


# =========================
# STATISTICS
# =========================

def get_statistics(connection):

    total_scans = connection.execute(
        "SELECT COUNT(*) FROM scans"
    ).fetchone()[0]

    safe_scans = connection.execute("""
        SELECT COUNT(*) FROM scans
        WHERE result = 'No Obvious Warning'
    """).fetchone()[0]

    review_scans = connection.execute("""
        SELECT COUNT(*) FROM scans
        WHERE result = 'Needs Review'
    """).fetchone()[0]

    suspicious_scans = connection.execute("""
        SELECT COUNT(*) FROM scans
        WHERE result = 'Potentially Suspicious'
    """).fetchone()[0]

    return (
        total_scans,
        safe_scans,
        review_scans,
        suspicious_scans
    )


# =========================
# DASHBOARD
# =========================

@app.route("/")
def home():

    connection = get_db_connection()

    scan_history = connection.execute("""
        SELECT * FROM scans
        ORDER BY id DESC
    """).fetchall()

    (
        total_scans,
        safe_scans,
        review_scans,
        suspicious_scans
    ) = get_statistics(connection)

    connection.close()

    return render_template(
        "index.html",
        scan_history=scan_history,
        total_scans=total_scans,
        safe_scans=safe_scans,
        review_scans=review_scans,
        suspicious_scans=suspicious_scans
    )


# =========================
# URL SCANNER PAGE
# =========================

@app.route("/scanner")
def scanner():

    return render_template("scanner.html")


# =========================
# SCAN HISTORY
# =========================

@app.route("/history")
def history():

    connection = get_db_connection()

    scan_history = connection.execute("""
        SELECT * FROM scans
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return render_template(
        "history.html",
        scan_history=scan_history
    )


# =========================
# SCAN DETAILS
# =========================

@app.route("/scan/<int:scan_id>")
def scan_details(scan_id):

    connection = get_db_connection()

    scan = connection.execute(
        "SELECT * FROM scans WHERE id = ?",
        (scan_id,)
    ).fetchone()

    connection.close()

    if scan is None:
        return "Scan not found", 404

    return render_template(
        "scan_details.html",
        scan=scan
    )


# =========================
# CLEAR HISTORY
# =========================

@app.route("/clear-history", methods=["POST"])
def clear_history():

    connection = get_db_connection()

    connection.execute(
        "DELETE FROM scans"
    )

    connection.commit()
    connection.close()

    return render_template(
        "history.html",
        scan_history=[]
    )


# =========================
# ANALYTICS
# =========================

@app.route("/analytics")
def analytics():

    connection = get_db_connection()

    scan_history = connection.execute("""
        SELECT * FROM scans
        ORDER BY id DESC
    """).fetchall()

    (
        total_scans,
        safe_scans,
        review_scans,
        suspicious_scans
    ) = get_statistics(connection)

    connection.close()

    return render_template(
        "analytics.html",
        scan_history=scan_history,
        total_scans=total_scans,
        safe_scans=safe_scans,
        review_scans=review_scans,
        suspicious_scans=suspicious_scans
    )


# =========================
# SETTINGS
# =========================

@app.route("/settings")
def settings():

    return render_template(
        "settings.html"
    )


# =========================
# EXPORT SCAN REPORT
# =========================

@app.route("/scan/<int:scan_id>/export")
def export_scan(scan_id):

    connection = get_db_connection()

    scan = connection.execute(
        "SELECT * FROM scans WHERE id = ?",
        (scan_id,)
    ).fetchone()

    connection.close()

    if scan is None:
        return "Scan not found", 404

    # Determine risk level

    if scan["score"] == 0:
        risk_level = "LOW"

    elif scan["score"] <= 2:
        risk_level = "MEDIUM"

    else:
        risk_level = "HIGH"

    reasons = scan["reasons"] or "Not available"

    # Create report

    report = f"""
PHISHGUARD SECURITY SCAN REPORT
================================

Scan ID:
{scan["id"]}

Scanned URL:
{scan["url"]}

Scanned At:
{scan["scanned_at"] or "Not available"}


RISK ASSESSMENT
===============

Risk Score:
{scan["score"]} / 10

Result:
{scan["result"]}

Risk Level:
{risk_level}


DETECTED INDICATORS
===================

{reasons.replace("; ", chr(10))}


IMPORTANT
=========

PhishGuard uses rule-based URL indicators.

A high risk score does not by itself prove that
a website is malicious, and a low score does not
guarantee that a website is safe.

This report is intended for security analysis
and educational purposes.
"""

    filename = f"phishguard_scan_{scan_id}.txt"

    return Response(
        report,
        mimetype="text/plain",
        headers={
            "Content-Disposition":
                f"attachment; filename={filename}"
        }
    )


# =========================
# URL SCANNING
# =========================

@app.route("/scan", methods=["POST"])
def scan():

    url = (
        request.form.get("url") or ""
    ).strip()

    parsed_url = urlparse(url)


    # =========================
    # URL VALIDATION
    # =========================

    if (
        parsed_url.scheme not in ["http", "https"]
        or not parsed_url.netloc
    ):

        connection = get_db_connection()

        scan_history = connection.execute("""
            SELECT * FROM scans
            ORDER BY id DESC
        """).fetchall()

        (
            total_scans,
            safe_scans,
            review_scans,
            suspicious_scans
        ) = get_statistics(connection)

        connection.close()

        return render_template(
            "scanner.html",
            error=(
                "Please enter a valid URL starting "
                "with http:// or https://."
            ),
            url=url,
            scan_history=scan_history,
            total_scans=total_scans,
            safe_scans=safe_scans,
            review_scans=review_scans,
            suspicious_scans=suspicious_scans
        )


    # =========================
    # INITIAL SCORE
    # =========================

    score = 0

    reasons = []


    # =========================
    # RULE 1: @ SYMBOL
    # =========================

    if "@" in url:

        score += 2

        reasons.append(
            "URL contains @ symbol"
        )


    # =========================
    # RULE 2: MULTIPLE HYPHENS
    # =========================

    if url.count("-") >= 3:

        score += 1

        reasons.append(
            "URL contains multiple hyphens"
        )


    # =========================
    # RULE 3: SECURITY KEYWORDS
    # =========================

    suspicious_keywords = [
        "login",
        "verify",
        "account",
        "secure",
        "update",
        "password"
    ]

    url_lower = url.lower()

    keyword_matches = [
        keyword
        for keyword in suspicious_keywords
        if keyword in url_lower
    ]

    if keyword_matches:

        score += 1

        reasons.append(
            "URL contains security-related keywords: "
            + ", ".join(keyword_matches)
        )


    # =========================
    # RULE 4: LONG URL
    # =========================

    if len(url) > 100:

        score += 1

        reasons.append(
            "URL is unusually long"
        )


    # =========================
    # RULE 5: HTTP
    # =========================

    if url.lower().startswith("http://"):

        score += 1

        reasons.append(
            "URL uses HTTP instead of HTTPS"
        )


    # =========================
    # RULE 6: IP ADDRESS
    # =========================

    is_ip_address = re.search(
        r"https?://\d{1,3}(\.\d{1,3}){3}",
        url
    )

    if is_ip_address:

        score += 2

        reasons.append(
            "URL uses an IP address instead of a domain name"
        )


    # =========================
    # RULE 7: NON-STANDARD PORT
    # =========================

    if (
        parsed_url.port
        and parsed_url.port not in [80, 443]
    ):

        score += 1

        reasons.append(
            "URL uses a non-standard port"
        )


    # =========================
    # RULE 8: MULTIPLE SUBDOMAINS
    # =========================

    hostname = parsed_url.hostname or ""

    # Important:
    # Do not treat an IPv4 address as a multi-level
    # subdomain structure.

    hostname_is_ip = re.fullmatch(
        r"\d{1,3}(\.\d{1,3}){3}",
        hostname
    )

    if not hostname_is_ip:

        domain_parts = hostname.split(".")

        if len(domain_parts) >= 4:

            score += 1

            reasons.append(
                "URL contains multiple subdomain levels"
            )


    # =========================
    # RULE 9: UNUSUAL DOMAIN CHARACTERS
    # =========================

    if re.search(
        r"[^a-zA-Z0-9.-]",
        hostname
    ):

        score += 1

        reasons.append(
            "Domain contains unusual or "
            "non-standard characters"
        )


    # =========================
    # DETERMINE RESULT
    # =========================

    if score >= 3:

        result = "Potentially Suspicious"

    elif score >= 1:

        result = "Needs Review"

    else:

        result = "No Obvious Warning"


    # =========================
    # TIMESTAMP
    # =========================

    scanned_at = datetime.now().strftime(
        "%d-%m-%Y %I:%M %p"
    )


    # =========================
    # SAVE REASONS
    # =========================

    reasons_text = "; ".join(
        reasons
    )

    if not reasons_text:

        reasons_text = (
            "No suspicious indicators detected"
        )


    # =========================
    # SAVE TO DATABASE
    # =========================

    connection = get_db_connection()

    connection.execute(
        """
        INSERT INTO scans
        (url, score, result, scanned_at, reasons)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            url,
            score,
            result,
            scanned_at,
            reasons_text
        )
    )

    connection.commit()


    # =========================
    # GET UPDATED HISTORY
    # =========================

    scan_history = connection.execute("""
        SELECT * FROM scans
        ORDER BY id DESC
    """).fetchall()


    # =========================
    # GET UPDATED STATISTICS
    # =========================

    (
        total_scans,
        safe_scans,
        review_scans,
        suspicious_scans
    ) = get_statistics(connection)


    connection.close()


    # =========================
    # SHOW RESULT
    # =========================

    return render_template(
        "scanner.html",
        url=url,
        score=score,
        result=result,
        reasons=reasons,
        scan_history=scan_history,
        total_scans=total_scans,
        safe_scans=safe_scans,
        review_scans=review_scans,
        suspicious_scans=suspicious_scans
    )


# =========================
# RUN APPLICATION
# =========================
create_table()
if __name__ == "__main__":
    app.run(
        debug=True
    )