from flask import Flask, render_template, request, redirect, url_for, jsonify
from firewall import init_firewall  # Importa il firewall personalizzato

app = Flask(__name__)

init_firewall(app)

@app.route('/')
def index():
    active_tab = request.args.get('tab', 'phone')
    return render_template('index.html', active_tab=active_tab)

@app.route('/phone', methods=['POST'])
def analyze_phone():
    phone_number = request.form.get('phone', '').strip()
    # Logica di analisi numero telefono
    result_text = f"Analisi completata per il numero: {phone_number}"
    return render_template('index.html', active_tab='phone', result=result_text)

@app.route('/ip', methods=['POST'])
def scan_ip():
    target_ip = request.form.get('ip', '').strip()
    # Logica di scansione IP e porte
    result_text = f"Scansione completata per IP: {target_ip}"
    return render_template('index.html', active_tab='ip', result=result_text)

@app.route('/ping')
def ping_speedtest():
    # End-point rapido per la misurazione della latenza (Ping)
    return jsonify({"status": "ok"})

@app.route('/submit_idea', methods=['POST'])
def submit_idea():
    tipo = request.form.get('tipo')
    messaggio = request.form.get('messaggio')
    # Salvataggio idea o feedback
    print(f"[FEEDBACK] Tipo: {tipo} | Messaggio: {messaggio}")
    return render_template('index.html', active_tab='submit', result="Grazie! Il tuo messaggio è stato inviato con successo.")

@app.route('/admin_login', methods=['POST'])
def admin_login():
    password = request.form.get('admin_password')
    # Controllo password amministratore
    if password == "LA_TUA_PASSWORD_ADMIN":
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
