import os
import re
import json
import socket
import sqlite3
from datetime import datetime, timedelta
import requests
import phonenumbers
from phonenumbers import carrier, geocoder, number_type
from flask import Flask, render_template, request, session, redirect, url_for

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", "chiave_segreta_di_default_cambiala_su_render")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

DB_NAME = "ip_history.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            user_agent TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def log_ip_access(ip, user_agent):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO ip_logs (ip, user_agent) VALUES (?, ?)", (ip, user_agent))
    cutoff_date = datetime.now() - timedelta(days=10)
    cursor.execute("DELETE FROM ip_logs WHERE timestamp < ?", (cutoff_date,))
    conn.commit()
    conn.close()

def get_ip_history():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cutoff_date = datetime.now() - timedelta(days=10)
    cursor.execute("DELETE FROM ip_logs WHERE timestamp < ?", (cutoff_date,))
    conn.commit()
    cursor.execute("SELECT ip, user_agent, timestamp FROM ip_logs ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return [{"ip": r[0], "user_agent": r[1], "timestamp": r[2]} for r in rows]

init_db()

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    else:
        ip = request.remote_addr
    return ip

def ip_lookup(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,continent,country,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting,query"
        r = requests.get(url, timeout=10)
        data = r.json()
        if data.get("status") != "success":
            return {"errore": data.get("message", "IP non valido")}
        return data
    except Exception as e:
        return {"errore": str(e)}

def scan_ports(ip, ports):
    RISCHI = {
        21: "FTP - credenziali in chiaro.",
        22: "SSH - rischio bruteforce.",
        23: "Telnet - RISCHIO ALTO.",
        25: "SMTP - rischio open relay.",
        53: "DNS - rischio amplification DDoS.",
        80: "HTTP - info disclosure.",
        110: "POP3 - posta in chiaro.",
        143: "IMAP - posta in chiaro.",
        443: "HTTPS - verifica certificato.",
        3306: "MySQL - esposto su internet.",
        3389: "RDP - bersaglio ransomware.",
        5900: "VNC - desktop remoto esposto.",
        8080: "HTTP Alt - pannelli admin."
    }
    risultati = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect((ip, p))
            risultati.append({"porta": p, "stato": "APERTA", "rischio": RISCHI.get(p, "Porta aperta")})
            s.close()
        except:
            risultati.append({"porta": p, "stato": "chiusa/filtrata", "rischio": "ok"})
    return risultati

MOBILE_PREFIX = {
    "330":"TIM","331":"TIM","333":"TIM","334":"TIM","335":"TIM","336":"TIM","337":"TIM","338":"TIM","339":"TIM","360":"TIM","361":"TIM","362":"TIM","363":"TIM","366":"TIM","368":"TIM",
    "340":"Vodafone","341":"Vodafone","342":"Vodafone","343":"Vodafone","345":"Vodafone","346":"Vodafone","347":"Vodafone","348":"Vodafone","349":"Vodafone",
    "320":"WindTre","321":"WindTre","322":"WindTre","323":"WindTre","324":"WindTre","325":"WindTre","326":"WindTre","327":"WindTre","328":"WindTre","329":"WindTre","380":"WindTre","381":"WindTre","383":"WindTre","388":"WindTre","389":"WindTre","391":"WindTre","392":"WindTre",
    "351":"Iliad","352":"Iliad","353":"Iliad","354":"Iliad","376":"Iliad","377":"Iliad",
    "350":"MVNO","370":"PosteMobile/Fastweb","371":"PosteMobile","373":"Kena/Fastweb","375":"ho. Mobile / Very","379":"ho. Mobile / Fastweb / CoopVoce"
}

FISSO_PREFIX = {
    "02":"Milano","06":"Roma","011":"Torino","010":"Genova","041":"Venezia","049":"Padova","051":"Bologna","055":"Firenze","070":"Cagliari","079":"Sassari","0789":"Olbia","081":"Napoli","080":"Bari","091":"Palermo"
}

def analyze_phone(raw):
    clean = re.sub(r'[^0-9+]', '', raw)
    if not clean.startswith('+'):
        if clean.startswith('00'):
            clean = '+' + clean[2:]
        elif clean.startswith('39'):
            clean = '+' + clean
        else:
            clean = '+39' + clean

    parsed = phonenumbers.parse(clean, "IT")
    valid = phonenumbers.is_valid_number(parsed)
    t = number_type(parsed)
    t_map = {0:"FISSO/MOBILE", 1:"FISSO", 2:"MOBILE", 3:"FISSO/MOBILE", 4:"TOLL FREE", 5:"PREMIUM"}
    tipo = t_map.get(t, str(t))

    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    nat = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    geo = geocoder.description_for_number(parsed, "it")

    nat_digits = re.sub(r'\D','', nat)
    p3 = nat_digits[:3]
    p2 = nat_digits[:2]
    op_db = MOBILE_PREFIX.get(p3, FISSO_PREFIX.get(nat_digits[:4], FISSO_PREFIX.get(p3, FISSO_PREFIX.get(p2, "Sconosciuto"))))
    num_wa = e164.replace('+','')

    return {
        "input_originale": raw,
        "numero_normalizzato": clean,
        "formato_e164": e164,
        "formato_nazionale": nat,
        "valido": valid,
        "tipo_linea": tipo,
        "posizione_geografica": geo if geo else "Italia",
        "operatore_originario_blocco": op_db,
        "collegamenti": {
            "whatsapp": f"https://wa.me/{num_wa}",
            "telegram": f"https://t.me/+{num_wa}"
        }
    }

@app.route('/')
def home():
    client_ip = get_client_ip()
    log_ip_access(client_ip, request.user_agent.string)
    return render_template('index.html', result=None, active_tab='phone', theme='')

@app.route('/ip', methods=['POST'])
def handle_ip():
    client_ip = get_client_ip()
    log_ip_access(client_ip, request.user_agent.string)

    ip = request.form.get('ip', '').strip()
    info = ip_lookup(ip)
    porte_comuni = [21,22,23,25,53,80,110,143,443,3306,3389,5900,8080]
    scan = scan_ports(ip, porte_comuni)
    output = {
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "lookup": info,
        "porte": scan
    }
    return render_template('index.html', result=json.dumps(output, indent=2, ensure_ascii=False), active_tab='ip', ip_val=ip)

@app.route('/phone', methods=['POST'])
def handle_phone():
    client_ip = get_client_ip()
    log_ip_access(client_ip, request.user_agent.string)

    phone = request.form.get('phone', '').strip()
    try:
        res = analyze_phone(phone)
        output = json.dumps(res, indent=2, ensure_ascii=False)
    except Exception as e:
        output = json.dumps({"errore": str(e)}, indent=2)
    return render_template('index.html', result=output, active_tab='phone', phone_val=phone)

@app.route('/admin/login', methods=['POST'])
def admin_login():
    input_password = request.form.get('password', '').strip()

    if ADMIN_PASSWORD and input_password == ADMIN_PASSWORD:
        session['admin_logged_in'] = True
        history = get_ip_history()
        return render_template(
            'index.html', 
            active_tab='admin', 
            history=json.dumps(history, indent=2, ensure_ascii=False)
        )
    else:
        return render_template(
            'index.html', 
            active_tab='admin', 
            error="Password non valida! Accesso negato."
        )

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
