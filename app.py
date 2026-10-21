import os
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, request, session, redirect, url_for
from games import games_bp

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "foundmyip_super_secret_key_2026")

app.register_blueprint(games_bp)

LOG_FILE = "ip_history.json"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def log_ip_access(ip_address, user_agent):
    now = datetime.utcnow()
    cutoff = now - timedelta(days=10)
    history = []

    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                history = json.load(f)
        except Exception:
            history = []

    valid_history = []
    for entry in history:
        try:
            entry_time = datetime.fromisoformat(entry["timestamp"])
            if entry_time > cutoff:
                valid_history.append(entry)
        except Exception:
            pass

    valid_history.append({
        "ip": ip_address,
        "timestamp": now.isoformat(),
        "user_agent": user_agent
    })

    with open(LOG_FILE, "w") as f:
        json.dump(valid_history, f, indent=2)

@app.before_request
def track_ip():
    client_ip = get_client_ip()
    log_ip_access(client_ip, request.user_agent.string)

@app.route("/")
def index():
    history_str = ""
    if session.get("admin_logged_in") and os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            history_str = f.read()

    return render_template("index.html", active_tab="phone", history=history_str)

@app.route("/phone", methods=["POST"])
def phone_analysis():
    phone_num = request.form.get("phone", "")
    res = f"Analisi completata per: {phone_num}\nPaese: Italia (+39)\nOperatore stimato: Mobile\nStato: Attivo"
    return render_template("index.html", active_tab="phone", result=res, phone_val=phone_num)

@app.route("/ip", methods=["POST"])
def ip_lookup():
    target_ip = request.form.get("ip", "")
    res = f"Scansione IP: {target_ip}\nStatus: Online\nPorte aperte: 80 (HTTP), 443 (HTTPS)"
    return render_template("index.html", active_tab="ip", result=res, ip_val=target_ip)

@app.route("/admin/login", methods=["POST"])
def admin_login():
    password = request.form.get("password", "")
    if password == ADMIN_PASSWORD:
        session["admin_logged_in"] = True
    else:
        return render_template("index.html", active_tab="admin", error="Password Errata!")
    return redirect(url_for("index"))

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
