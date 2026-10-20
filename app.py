import os
import re
import json
import socket
from datetime import datetime
import requests
import phonenumbers
from phonenumbers import carrier, geocoder, number_type
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# --- LOGICA SCRIPT 1: IP LOOKUP & PORT SCAN ---
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
        21: "FTP - credenziali in chiaro. Usa SFTP.",
        22: "SSH - rischio bruteforce. Usa chiavi.",
        23: "Telnet - RISCHIO ALTO, non criptato.",
        25: "SMTP - rischio open relay spam.",
        53: "DNS - rischio amplification DDoS.",
        80: "HTTP - info disclosure.",
        110: "POP3 - posta in chiaro.",
        143: "IMAP - posta in chiaro.",
        443: "HTTPS - verifica certificato e TLS.",
        3306: "MySQL - RISCHIO ALTO se esposto.",
        3389: "RDP - RISCHIO ALTO. Usa VPN.",
        5900: "VNC - desktop remoto esposto.",
        8080: "HTTP Alt - pannelli admin esposti."
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

# --- LOGICA SCRIPT 2: PHONE ANALYZER ---
MOBILE_PREFIX = {
    "330":"TIM","331":"TIM","333":"TIM","334":"TIM","335":"TIM","336":"TIM","337":"TIM","338":"TIM","339":"TIM","360":"TIM","361":"TIM","362":"TIM","363":"TIM","366":"TIM","368":"TIM",
    "340":"Vodafone","341":"Vodafone","342":"Vodafone","343":"Vodafone","345":"Vodafone","346":"Vodafone","347":"Vodafone","348":"Vodafone","349":"Vodafone",
    "320":"WindTre","321":"WindTre","322":"WindTre","323":"WindTre","324":"WindTre","325":"WindTre","326":"WindTre","327":"WindTre","328":"WindTre","329":"WindTre","380":"WindTre","381":"WindTre","383":"WindTre","388":"WindTre","389":"WindTre","391":"WindTre","392":"WindTre",
    "351":"Iliad","352":"Iliad","353":"Iliad","354":"Iliad","376":"Iliad","377":"Iliad",
    "350":"MVNO","370":"PosteMobile/Fastweb","371":"PosteMobile","373":"Kena/Fastweb","375":"Ho./Very","379":"CoopVoce/Fastweb"
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
    t_map = {0:"FISSO/MOBILE",1:"FISSO",2:"MOBILE",3:"FISSO/MOBILE",4:"TOLL FREE",5:"PREMIUM"}
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
        "input": raw,
        "normalized": clean,
        "e164": e164,
        "international": intl,
        "national": nat,
        "valid": valid,
        "possible": possible,
        "type": tipo,
        "geo": geo,
        "carrier_lib": carr_lib if carr_lib else "N/D",
        "operator_origin_db": op_db,
        "links": {
            "whatsapp": f"https://wa.me/{num_wa}",
            "telegram": f"https://t.me/+{num_wa}"
        }
    }

# --- INTERFACCIA WEB SEMPLICE ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <title>Tool OSINT Web</title>
    <style>
        body { font-family: Arial, sans-serif; background: #121212; color: #e0e0e0; padding: 20px; max-width: 800px; margin: auto; }
        h1 { color: #bb86fc; }
        .box { background: #1e1e1e; padding: 15px; margin-bottom: 20px; border-radius: 8px; border: 1px solid #333; }
        input, button { padding: 10px; margin-top: 5px; width: 100%; box-sizing: border-box; background: #2d2d2d; color: white; border: 1px solid #444; border-radius: 4px; }
        button { background: #bb86fc; color: black; font-weight: bold; cursor: pointer; }
        button:hover { background: #9965f4; }
        pre { background: #000; padding: 10px; border-radius: 4px; overflow-x: auto; color: #03dac6; }
    </style>
</head>
<body>
    <h1>Tool OSINT Web Dashboard</h1>
    
    <div class="box">
        <h3>1. IP Lookup & Port Scan</h3>
        <form method="POST" action="/ip">
            <input type="text" name="ip" placeholder="Inserisci IP (es. 8.8.8.8)" required>
            <button type="submit">Esegui Scansione IP</button>
        </form>
    </div>

    <div class="box">
        <h3>2. Phone Number Analyzer</h3>
        <form method="POST" action="/phone">
            <input type="text" name="phone" placeholder="Inserisci Numero (es. +393331234567)" required>
            <button type="submit">Analizza Numero</button>
        </form>
    </div>

    {% if result %}
    <div class="box">
        <h3>Risultato:</h3>
        <pre>{{ result }}</pre>
    </div>
    {% endif %}
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE, result=None)

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
    return render_template_string(HTML_TEMPLATE, result=json.dumps(output, indent=2, ensure_ascii=False))

@app.route('/phone', methods=['POST'])
def handle_phone():
    phone = request.form.get('phone', '').strip()
    try:
        res = analyze_phone(phone)
        output = json.dumps(res, indent=4, ensure_ascii=False)
    except Exception as e:
        output = json.dumps({"errore": str(e)}, indent=4)
    return render_template_string(HTML_TEMPLATE, result=output)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
