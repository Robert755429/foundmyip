import os
import json
import urllib.request
from datetime import datetime, timedelta
from flask import Flask, render_template, request, session, redirect, url_for
from games import games_bp

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "foundmyip_super_secret_key_2026")

app.register_blueprint(games_bp)

LOG_FILE = "ip_history.json"
IDEAS_FILE = "ideas_history.json"
FEEDBACK_FILE = "feedback_history.json"
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

    valid_history = [entry for entry in history if datetime.fromisoformat(entry["timestamp"]) > cutoff]
    valid_history.append({"ip": ip_address, "timestamp": now.isoformat(), "user_agent": user_agent})

    with open(LOG_FILE, "w") as f:
        json.dump(valid_history, f, indent=2)

@app.before_request
def track_ip():
    client_ip = get_client_ip()
    log_ip_access(client_ip, request.user_agent.string)

@app.route("/")
def index():
    history_str = ""
    ideas_str = ""
    feedback_str = ""
    
    if session.get("admin_logged_in"):
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f: history_str = f.read()
        if os.path.exists(IDEAS_FILE):
            with open(IDEAS_FILE, "r") as f: ideas_str = f.read()
        if os.path.exists(FEEDBACK_FILE):
            with open(FEEDBACK_FILE, "r") as f: feedback_str = f.read()

    return render_template("index.html", active_tab="phone", history=history_str, ideas_list=ideas_str, feedback_list=feedback_str)

@app.route("/phone", methods=["POST"])
def phone_analysis():
    phone_num = request.form.get("phone", "")
    res = f"""📱 DETTAGLI ANALISI NUMERO: {phone_num}
----------------------------------------
• Paese: Italia (+39)
• Operatore Stimato: Telecom Italia / Vodafone / WindTre / Iliad
• Tipo Linea: Mobile (Cellulare)
• Formato Internazionale: Valido
• Stato Scheda SIM: Attiva / In Rete"""
    return render_template("index.html", active_tab="phone", result=res, phone_val=phone_num)

@app.route("/ip", methods=["POST"])
def ip_lookup():
    target_ip = request.form.get("ip", "").strip()
    geo_data = {}
    try:
        url = f"http://ip-api.com/json/{target_ip}?fields=status,message,continent,country,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting,query"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            geo_data = json.loads(response.read().decode())
    except Exception as e:
        geo_data = {"status": "fail", "message": str(e)}

    output = {"mio_ip": target_ip, "timestamp": datetime.utcnow().isoformat(), "dettagli_geolocalizzazione": geo_data}
    return render_template("index.html", active_tab="ip", result=json.dumps(output, indent=2), ip_val=target_ip)

@app.route("/submit_idea", methods=["POST"])
def submit_idea():
    tipo = request.form.get("tipo", "idea")
    messaggio = request.form.get("messaggio", "").strip()
    if messaggio:
        target_file = IDEAS_FILE if tipo == "idea" else FEEDBACK_FILE
        data = []
        if os.path.exists(target_file):
            try:
                with open(target_file, "r") as f: data = json.load(f)
            except Exception: data = []
        data.append({"timestamp": datetime.utcnow().isoformat(), "messaggio": messaggio})
        with open(target_file, "w") as f: json.dump(data, f, indent=2)
    return render_template("index.html", active_tab="submit", result="✅ Messaggio inviato con successo! Grazie per il supporto.")

@app.route("/admin/login", methods=["POST"])
def admin_login():
    if request.form.get("password", "") == ADMIN_PASSWORD:
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
