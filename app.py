import os
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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
