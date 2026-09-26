from flask import Flask, render_template, request
from d import detect_scam
from database import init_db, save_scan
import sqlite3

app = Flask(__name__)

init_db()


@app.route("/", methods=["GET", "POST"])
def home():
    risk = None
    score = 0
    reasons = []
    category = ""
    confidence = 0
    intent = ""
    message = ""

    if request.method == "POST":
        message = request.form["message"]

        risk, score, reasons, category, confidence, intent = detect_scam(message)

        save_scan(
            message,
            risk,
            score,
            category,
            confidence,
            intent
        )

    return render_template(
        "index.html",
        risk=risk,
        score=score,
        reasons=reasons,
        category=category,
        confidence=confidence,
        intent=intent,
        message=message
    )


@app.route("/history")
def history():
    conn = sqlite3.connect("scamshield.db")

    scans = conn.execute("""
        SELECT id, message, risk, score, category, confidence, intent
        FROM scans
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template("history.html", scans=scans)


@app.route("/dashboard")
def dashboard():
    conn = sqlite3.connect("scamshield.db")

    total = conn.execute(
        "SELECT COUNT(*) FROM scans"
    ).fetchone()[0]

    high = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE risk = 'HIGH RISK'"
    ).fetchone()[0]

    suspicious = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE risk = 'SUSPICIOUS'"
    ).fetchone()[0]

    low = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE risk = 'LOW RISK'"
    ).fetchone()[0]

    conn.close()

    return render_template(
        "dashboard.html",
        total=total,
        high=high,
        suspicious=suspicious,
        low=low
    )


if __name__ == "__main__":
    app.run(debug=True)