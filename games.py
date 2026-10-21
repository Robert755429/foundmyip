from flask import Blueprint, render_template

games_bp = Blueprint('games', __name__, url_prefix='/game')

@games_bp.route('/platformer')
def platformer():
    return render_template('games/platformer.html')

@games_bp.route('/lucchetto')
def lucchetto():
    return render_template('games/lucchetto.html')

@games_bp.route('/blockblast')
def blockblast():
    return render_template('games/blockblast.html')

@games_bp.route('/guesstheflag')
def guesstheflag():
    return render_template('games/guesstheflag.html')
