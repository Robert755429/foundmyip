import os
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Rotta Principale (Home Page)
@app.route('/')
def home():
    return render_template('index.html')

# Rotte per i Giochi
@app.route('/games/platformer')
def platformer_game():
    return render_template('games/platformer.html')

@app.route('/games/guesstheflag')
def guesstheflag_game():
    return render_template('games/guesstheflag.html')

@app.route('/games/pong')
def pong_game():
    return render_template('games/pong.html')

@app.route('/games/tris')
def tris_game():
    return render_template('games/tris.html')

@app.route('/games/game2048')
def game2048_game():
    return render_template('games/game2048.html')

@app.route('/games/lock')
def lock_game():
    return render_template('games/lock.html')

# Rotta per la Verifica Email e reCAPTCHA
@app.route('/verify', methods=['GET', 'POST'])
def verify_user():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        recaptcha_response = request.form.get('g-recaptcha-response')
        
        # Recupera la Secret Key dalle variabili d'ambiente di Render o inseriscila qui
        secret_key = os.environ.get('RECAPTCHA_SECRET_KEY', 'INSERISCI_QUI_LA_TUA_SECRET_KEY')
        
        payload = {
            'secret': secret_key,
            'response': recaptcha_response
        }
        
        # Richiesta di verifica a Google
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
        result = response.json()
        
        if result.get('success'):
            return render_template('components/verify_success.html', email=email)
        else:
            error = "Per favore, completa il reCAPTCHA per dimostrare di non essere un robot."
            
    return render_template('components/verify.html', error=error)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
