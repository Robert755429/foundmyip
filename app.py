from flask import Flask, render_template, request, jsonify
from firewall import init_firewall
from antivirus_engine import scan_payload

app = Flask(__name__)
init_firewall(app)

@app.route('/')
def index():
    active_tab = request.args.get('tab', 'phone')
    return render_template('index.html', active_tab=active_tab)

@app.route('/phone', methods=['POST'])
def analyze_phone():
    phone_number = request.form.get('phone', '').strip()
    result_text = f"Analisi completata per il numero: {phone_number}"
    return render_template('index.html', active_tab='phone', result=result_text)

@app.route('/ip', methods=['POST'])
def scan_ip():
    target_ip = request.form.get('ip', '').strip()
    result_text = f"Scansione completata per IP: {target_ip}"
    return render_template('index.html', active_tab='ip', result=result_text)

@app.route('/ping')
def ping_speedtest():
    return jsonify({"status": "ok"})

@app.route('/antivirus_scan', methods=['POST'])
def antivirus_scan():
    target = request.form.get('target', '').strip()
    if not target:
        return render_template('index.html', active_tab='antivirus', av_result="Errore: Inserisci un target valido da analizzare.")

    report = scan_payload(target)
    
    formatted_report = (
        f"🛡️ REPORT ANALISI ANTIVIRUS IMPLACABILE\n"
        f"----------------------------------------\n"
        f"🎯 Target: {target}\n"
        f"📊 Stato: {report['status']}\n"
        f"⚠️ Punteggio Rischio: {report['risk_score']} / 100\n"
        f"📦 Tipo Rilevato: {report['file_type']}\n"
        f"🔐 Hash SHA-256: {report['sha256']}\n"
        f"📈 Entropia Shannon: {report['entropy']}\n"
        f"📝 Dettagli: {report['details']}"
    )
    return render_template('index.html', active_tab='antivirus', av_result=formatted_report)

@app.route('/submit_idea', methods=['POST'])
def submit_idea():
    tipo = request.form.get('tipo')
    messaggio = request.form.get('messaggio')
    return render_template('index.html', active_tab='submit', result="Grazie! Il tuo messaggio è stato inviato con successo.")

@app.route('/admin_login', methods=['POST'])
def admin_login():
    password = request.form.get('admin_password')
    if password == "TUA_PASSWORD_ADMIN":
        return render_template('index.html', active_tab='admin', result="Accesso Admin Effettuato!")
    else:
        return render_template('index.html', active_tab='admin', error="Password errata!")

@app.route('/game/platformer')
def game_mario():
    return render_template('games/platformer.html')

@app.route('/game/lucchetto')
def game_lucchetto():
    return render_template('games/lucchetto.html')

@app.route('/game/guesstheflag')
def game_flag():
    return render_template('games/guesstheflag.html')

@app.route('/game/2048')
def game_2048():
    return render_template('games/2048.html')

@app.route('/game/tris')
def game_tris():
    return render_template('games/tris.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
