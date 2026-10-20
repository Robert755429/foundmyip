import os
import re
import json
import socket
from datetime import datetime
import requests
import phonenumbers
from phonenumbers import carrier, geocoder, number_type
from flask import Flask, render_template_string, request

app = Flask(__name__)

# --- IP LOOKUP & PORT SCAN ---
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

# --- PHONE ANALYZER ---
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
    possible = phonenumbers.is_possible_number(parsed)
    t = number_type(parsed)
    t_map = {0:"FISSO/MOBILE", 1:"FISSO", 2:"MOBILE", 3:"FISSO/MOBILE", 4:"TOLL FREE", 5:"PREMIUM"}
    tipo = t_map.get(t, str(t))

    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    nat = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    geo = geocoder.description_for_number(parsed, "it")
    carr_lib = carrier.name_for_number(parsed, "it")

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
        "nota_portabilita": "Se l'utente ha fatto MNP (portabilità), l'operatore attuale (es. ho. Mobile) può variare rispetto a quello nativo.",
        "collegamenti": {
            "whatsapp": f"https://wa.me/{num_wa}",
            "telegram": f"https://t.me/+{num_wa}"
        }
    }

# --- TEMPLATE HTML ---
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
            justify-content: center;
            transition: background 0.3s ease;
        }

        .container {
            width: 100%;
            max-width: 650px;
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
            gap: 10px;
            margin-bottom: 20px;
        }

        .tab-btn {
            flex: 1;
            padding: 14px;
            text-align: center;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-color);
            font-weight: bold;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.2s;
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
            padding: 14px;
            margin: 10px 0 20px 0;
            background: var(--input-bg);
            color: var(--text-color);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            font-size: 1rem;
            box-sizing: border-box;
        }

        button.action-btn {
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
        }

        button.action-btn:hover {
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

        <div class="nav-tabs">
            <button class="tab-btn {% if active_tab == 'phone' %}active{% endif %}" onclick="switchTab('phone')">📱 Telefono</button>
            <button class="tab-btn {% if active_tab == 'ip' %}active{% endif %}" onclick="switchTab('ip')">🌐 Indirizzo IP</button>
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

        <!-- SCHEDA IP -->
        <div id="ip-card" class="card {% if active_tab == 'ip' %}active{% endif %}">
            <h3>Lookup IP & Porte</h3>
            <form method="POST" action="/ip">
                <label>Inserisci IP (es. 8.8.8.8)</label>
                <input type="text" name="ip" placeholder="8.8.8.8..." value="{{ ip_val or '' }}" required>
                <button type="submit" class="action-btn">Scansiona Indirizzo IP</button>
            </form>
        </div>

        {% if result %}
        <div class="card active">
            <h3>Risultato Elaborazione:</h3>
            <pre>{{ result }}</pre>
        </div>
        {% endif %}
    </div>

    <script>
        function switchTab(tab) {
            document.getElementById('phone-card').classList.remove('active');
            document.getElementById('ip-card').classList.remove('active');
            const btns = document.querySelectorAll('.tab-btn');
            btns.forEach(b => b.classList.remove('active'));

            if(tab === 'phone') {
                document.getElementById('phone-card').classList.add('active');
                btns[0].classList.add('active');
            } else {
                document.getElementById('ip-card').classList.add('active');
                btns[1].classList.add('active');
            }
        }

        function changeTheme(theme) {
            document.body.className = '';
            if(theme !== 'cyber') {
                document.body.classList.add('theme-' + theme);
            }
            localStorage.setItem('selected_theme', theme);
        }

        window.onload = function() {
            const savedTheme = localStorage.getItem('selected_theme');
            if(savedTheme) {
                document.getElementById('themeSelect').value = savedTheme;
                changeTheme(savedTheme);
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE, result=None, active_tab='phone', theme='')

@app.route('/ip', methods=['POST'])
def handle_ip():
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
    phone = request.form.get('phone', '').strip()
    try:
        res = analyze_phone(phone)
        output = json.dumps(res, indent=2, ensure_ascii=False)
    except Exception as e:
        output = json.dumps({"errore": str(e)}, indent=2)
    return render_template_string(HTML_TEMPLATE, result=output, active_tab='phone', phone_val=phone)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
