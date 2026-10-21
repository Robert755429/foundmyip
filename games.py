from flask import Blueprint, render_template

games_bp = Blueprint('games', __name__, url_prefix='/game')

@games_bp.route('/platformer')
def platformer():
    return render_template('games/platformer.html')

@games_bp.route('/lucchetto')
def lucchetto():
    return render_template('games/lucchetto.html')

@games_bp.route('/guesstheflag')
def guesstheflag():
    return render_template('games/guesstheflag.html')
    
@games_bp.route('/2048')
def game_2048():
    return render_template('games/game2048.html')

@games_bp.route('/tris')
def tris():
    return render_template('games/tris.html')
