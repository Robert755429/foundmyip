import os
import re
import json
import socket
import sqlite3
from datetime import datetime, timedelta
import requests
import phonenumbers
from phonenumbers import carrier, geocoder, number_type
from flask import Flask, render_template_string, request, session, redirect, url_for

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", "chiave_segreta_di_default_cambiala_su_render")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Nicola11.")

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

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Dashboard Pro</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-color: #f8fafc;
            --accent-color: #8b5cf6;
            --accent-hover: #7c3aed;
            --input-bg: #090d16;
            --border-color: #334155;
        }

        body.theme-matrix {
            --bg-color: #022c22;
            --card-bg: #064e3b;
            --accent-color: #10b981;
            --accent-hover: #059669;
        }

        body.theme-ocean {
            --bg-color: #082f49;
            --card-bg: #0369a1;
            --accent-color: #38bdf8;
            --accent-hover: #0ea5e9;
        }

        body.theme-light {
            --bg-color: #f1f5f9;
            --card-bg: #ffffff;
            --text-color: #0f172a;
            --accent-color: #6366f1;
            --accent-hover: #4f46e5;
            --input-bg: #f8fafc;
            --border-color: #cbd5e1;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            min-height: 100vh;
            transition: background 0.3s ease;
            box-sizing: border-box;
        }

        .container {
            width: 100%;
            max-width: 700px;
            flex: 1;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            background: var(--card-bg);
            padding: 15px 20px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.2);
            border: 1px solid var(--border-color);
        }

        h1 {
            font-size: 1.4rem;
            margin: 0;
            color: var(--accent-color);
        }

        .theme-selector select {
            background: var(--input-bg);
            color: var(--text-color);
            border: 1px solid var(--border-color);
            padding: 6px 10px;
            border-radius: 6px;
            cursor: pointer;
        }

        .nav-tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        .tab-btn {
            flex: 1;
            min-width: 120px;
            padding: 12px;
            text-align: center;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-color);
            font-weight: bold;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            font-size: 0.9rem;
        }

        .tab-btn.active {
            background: var(--accent-color);
            color: #ffffff;
            border-color: var(--accent-color);
        }

        .card {
            background: var(--card-bg);
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 8px 16px rgba(0,0,0,0.3);
            border: 1px solid var(--border-color);
            margin-bottom: 20px;
            display: none;
        }

        .card.active {
            display: block;
        }

        h3 {
            margin-top: 0;
            color: var(--accent-color);
        }

        input {
            width: 100%;
            padding: 12px;
            margin: 8px 0 16px 0;
            background: var(--input-bg);
            color: var(--text-color);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            font-size: 1rem;
            box-sizing: border-box;
        }

        button.action-btn, a.action-btn {
            display: inline-block;
            text-align: center;
            width: 100%;
            padding: 14px;
            background: var(--accent-color);
            color: #ffffff;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.2s;
            text-decoration: none;
            box-sizing: border-box;
        }

        button.action-btn:hover, a.action-btn:hover {
            background: var(--accent-hover);
        }

        pre {
            background: #020617;
            color: #38bdf8;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.9rem;
            border: 1px solid var(--border-color);
        }

        .alert-error {
            background: #7f1d1d;
            color: #fca5a5;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 15px;
            border: 1px solid #991b1b;
        }

        /* Overlay di blocco per i cookie */
        #cookie-overlay {
            display: none;
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(15, 23, 42, 0.95);
            z-index: 9999;
            justify-content: center;
            align-items: center;
            padding: 20px;
            box-sizing: border-box;
        }

        .cookie-box {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 30px;
            border-radius: 12px;
            max-width: 450px;
            text-align: center;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
        }

        .cookie-box h3 {
            margin-top: 0;
            color: var(--accent-color);
        }

        .cookie-box p {
            font-size: 0.9rem;
            line-height: 1.5;
            margin-bottom: 20px;
        }

        footer {
            margin-top: auto;
            width: 100%;
            max-width: 700px;
            text-align: center;
            padding: 20px 0 10px 0;
            font-size: 0.8rem;
            color: #94a3b8;
            border-top: 1px solid var(--border-color);
        }

        footer a {
            color: var(--accent-color);
            text-decoration: none;
            margin: 0 5px;
        }

        footer a:hover {
            text-decoration: underline;
        }

        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.8);
            justify-content: center;
            align-items: center;
            z-index: 2000;
        }

        .modal-content {
            background: var(--card-bg);
            padding: 25px;
            border-radius: 12px;
            max-width: 500px;
            max-height: 80vh;
            overflow-y: auto;
            border: 1px solid var(--border-color);
        }

        .modal-close {
            float: right;
            cursor: pointer;
            font-size: 1.2rem;
            font-weight: bold;
        }
    </style>
</head>
<body class="{{ theme }}">
    <div class="container">
        <header>
            <h1>🔍 OSINT Dashboard</h1>
            <div class="theme-selector">
                <select id="themeSelect" onchange="changeTheme(this.value)">
                    <option value="cyber">Cyber Viola</option>
                    <option value="matrix">Matrix Verde</option>
                    <option value="ocean">Oceano Blu</option>
                    <option value="light">Tema Chiaro</option>
                </select>
            </div>
        </header>

        {% if error %}
            <div class="alert-error">{{ error }}</div>
        {% endif %}

        <div class="nav-tabs">
            <button class="tab-btn {% if active_tab == 'phone' %}active{% endif %}" onclick="switchTab('phone')">📱 Telefono</button>
            <button class="tab-btn {% if active_tab == 'ip' %}active{% endif %}" onclick="switchTab('ip')">🌐 IP Lookup</button>
            <button class="tab-btn {% if active_tab == 'myip' %}active{% endif %}" onclick="switchTab('myip')">📍 Il Mio IP</button>
            <button class="tab-btn {% if active_tab == 'admin' %}active{% endif %}" onclick="switchTab('admin')">🔐 Area Admin</button>
        </div>

        <!-- SCHEDA TELEFONO -->
        <div id="phone-card" class="card {% if active_tab == 'phone' %}active{% endif %}">
            <h3>Analizzatore Numeri</h3>
            <form method="POST" action="/phone">
                <label>Inserisci Numero (es. +393792638352)</label>
                <input type="text" name="phone" placeholder="+39..." value="{{ phone_val or '' }}" required>
                <button type="submit" class="action-btn">Avvia Analisi Telefono</button>
            </form>
        </div>

        <!-- SCHEDA IP SCANNER -->
        <div id="ip-card" class="card {% if active_tab == 'ip' %}active{% endif %}">
            <h3>Lookup IP & Porte</h3>
            <form method="POST" action="/ip">
                <label>Inserisci IP (es. 8.8.8.8)</label>
                <input type="text" name="ip" placeholder="8.8.8.8..." value="{{ ip_val or '' }}" required>
                <button type="submit" class="action-btn">Scansiona Indirizzo IP</button>
            </form>
        </div>

        <!-- SCHEDA IL MIO IP -->
        <div id="myip-card" class="card {% if active_tab == 'myip' %}active{% endif %}">
            <h3>Localizza il tuo Indirizzo IP</h3>
            <p>Ottieni il tuo IP e la posizione esatta unita al GPS del dispositivo.</p>
            
            <button type="button" class="action-btn" onclick="getLocalIpAndGPS()" style="background: var(--accent-color);">📍 Localizza il Mio IP Adesso</button>
            
            <pre id="myip-result" style="margin-top: 15px; display: none;"></pre>
        </div>

        <!-- SCHEDA ADMIN LOGIN / DASHBOARD -->
        <div id="admin-card" class="card {% if active_tab == 'admin' %}active{% endif %}">
            {% if session.get('admin_logged_in') %}
                <h3>🔐 Cronologia IP (Area Riservata Creator)</h3>
                <p style="font-size: 0.85rem; color: #a7f3d0;">* Nota: Gli IP vengono memorizzati e puliti automaticamente dopo 10 giorni.</p>
                <a href="/admin/logout" style="color: #fca5a5; display: inline-block; margin-bottom: 15px; text-decoration: none;">🚪 Effettua Logout</a>
                
                {% if history %}
                    <pre>{{ history }}</pre>
                {% else %}
                    <p>Nessun IP registrato negli ultimi 10 giorni.</p>
                {% endif %}
            {% else %}
                <h3>🔐 Accesso Riservato Creatore</h3>
                <form method="POST" action="/admin/login">
                    <label>Password Amministratore</label>
                    <input type="password" name="password" placeholder="Inserisci la password..." required>
                    <button type="submit" class="action-btn">Accedi alla Cronologia IP</button>
                </form>
            {% endif %}
        </div>

        {% if result %}
        <div class="card active">
            <h3>Risultato Elaborazione:</h3>
            <pre>{{ result }}</pre>
        </div>
        {% endif %}
    </div>

    <footer>
        <p>&copy; 2026 OSINT Dashboard. Tutti i diritti riservati.</p>
        <p>Licenza: <strong>MIT License</strong> | Copyright &copy; <strong>Nix</strong></p>
        <p>
            <a href="#" onclick="openModal('privacyModal')">Informativa sulla Privacy & Cookie</a> | 
            <a href="#" onclick="openModal('termsModal')">Termini di Servizio</a>
        </p>
    </footer>

    <!-- OVERLAY BLOCCO COOKIE MANDATORIO -->
    <div id="cookie-overlay">
        <div class="cookie-box">
            <h3>🔒 Accettazione Cookie Richiesta</h3>
            <p>Per poter utilizzare la OSINT Dashboard e usufruire dei nostri strumenti, è obbligatorio accettare l'utilizzo dei cookie tecnici e l'informativa sulla privacy.</p>
            <button class="action-btn" onclick="acceptCookies()">Accetta e Prosegui</button>
            <p style="margin-top: 15px; font-size: 0.8rem;">
                <a href="#" onclick="openModal('privacyModal')" style="color:var(--accent-color);">Leggi la Privacy Policy</a>
            </p>
        </div>
    </div>

    <div id="privacyModal" class="modal">
        <div class="modal-content">
            <span class="modal-close" onclick="closeModal('privacyModal')">&times;</span>
            <h3>Informativa sulla Privacy & Cookie Policy</h3>
            <p><strong>1. Trattamento dei Dati:</strong> Questo sito web registra gli indirizzi IP dei visitatori e i dati di navigazione basilari (User Agent) a fini di sicurezza.</p>
            <p><strong>2. Conservazione:</strong> Gli indirizzi IP memorizzati vengono eliminati automaticamente dopo 10 giorni.</p>
            <p><strong>3. Cookie:</strong> Vengono utilizzati cookie tecnici necessari per il funzionamento e l'autenticazione.</p>
        </div>
    </div>

    <div id="termsModal" class="modal">
        <div class="modal-content">
            <span class="modal-close" onclick="closeModal('termsModal')">&times;</span>
            <h3>Termini e Condizioni</h3>
            <p>Strumento fornito a scopo didattico e di verifica personale.</p>
        </div>
    </div>

    <script>
        async function getLocalIpAndGPS() {
            const resBox = document.getElementById('myip-result');
            resBox.style.display = 'block';
            resBox.textContent = "Rilevamento IP di rete in corso...";

            try {
                const ipResponse = await fetch('https://api.ipify.org?format=json');
                const ipData = await ipResponse.json();
                const clientIp = ipData.ip;

                resBox.textContent = "IP rilevato: " + clientIp + "\\nRichiesta posizione GPS...";

                if (navigator.geolocation) {
                    navigator.geolocation.getCurrentPosition(
                        (position) => {
                            const lat = position.coords.latitude;
                            const lon = position.coords.longitude;
                            const acc = position.coords.accuracy;

                            const output = {
                                "mio_ip": clientIp,
                                "timestamp": new Date().toISOString(),
                                "latitudine": lat,
                                "longitudine": lon,
                                "precisione_metri": acc,
                                "link_google_maps": `https://www.google.com/maps?q=${lat},${lon}`,
                                "nota": "IP corretto unito alla posizione GPS reale del dispositivo."
                            };
                            resBox.textContent = JSON.stringify(output, null, 2);
                        },
                        (error) => {
                            resBox.textContent = JSON.stringify({
                                "mio_ip": clientIp,
                                "errore_gps": "Permesso di localizzazione negato o non disponibile: " + error.message,
                                "nota": "Impossibile mostrare la posizione esatta senza il permesso GPS."
                            }, null, 2);
                        },
                        { enableHighAccuracy: true }
                    );
                } else {
                    resBox.textContent = "IP: " + clientIp + "\\nGeolocalizzazione GPS non supportata dal browser.";
                }
            } catch (err) {
                resBox.textContent = "Errore durante il recupero dell'indirizzo IP: " + err.message;
            }
        }

        function switchTab(tab) {
            document.querySelectorAll('.card').forEach(c => c.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));

            const card = document.getElementById(tab + '-card');
            if(card) card.classList.add('active');

            const btns = document.querySelectorAll('.tab-btn');
            if(tab === 'phone') btns[0].classList.add('active');
            if(tab === 'ip') btns[1].classList.add('active');
            if(tab === 'myip') btns[2].classList.add('active');
            if(tab === 'admin') btns[3].classList.add('active');
        }

        function changeTheme(theme) {
            document.body.className = '';
            if(theme !== 'cyber') {
                document.body.classList.add('theme-' + theme);
            }
            localStorage.setItem('selected_theme', theme);
        }

        function acceptCookies() {
            localStorage.setItem('cookies_accepted', 'true');
            document.getElementById('cookie-overlay').style.display = 'none';
        }

        function openModal(id) {
            document.getElementById(id).style.display = 'flex';
        }

        function closeModal(id) {
            document.getElementById(id).style.display = 'none';
        }

        window.onload = function() {
            const savedTheme = localStorage.getItem('selected_theme');
            if(savedTheme) {
                document.getElementById('themeSelect').value = savedTheme;
                changeTheme(savedTheme);
            }

            // Blocca il sito se non ha accettato i cookie
            if(!localStorage.getItem('cookies_accepted')) {
                document.getElementById('cookie-overlay').style.display = 'flex';
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    client_ip = get_client_ip()
    log_ip_access(client_ip, request.user_agent.string)
    return render_template_string(HTML_TEMPLATE, result=None, active_tab='phone', theme='')

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
    return render_template_string(HTML_TEMPLATE, result=json.dumps(output, indent=2, ensure_ascii=False), active_tab='ip', ip_val=ip)

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
    return render_template_string(HTML_TEMPLATE, result=output, active_tab='phone', phone_val=phone)

@app.route('/admin/login', methods=['POST'])
def admin_login():
    input_password = request.form.get('password', '').strip()

    if ADMIN_PASSWORD and input_password == ADMIN_PASSWORD:
        session['admin_logged_in'] = True
        history = get_ip_history()
        return render_template_string(
            HTML_TEMPLATE, 
            active_tab='admin', 
            history=json.dumps(history, indent=2, ensure_ascii=False)
        )
    else:
        return render_template_string(
            HTML_TEMPLATE, 
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
