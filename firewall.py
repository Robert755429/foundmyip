import re
import time
from collections import defaultdict
from flask import request, abort

# -------------------------------------------------------------------
# CONFIGURAZIONE FIREWALL
# -------------------------------------------------------------------

# IP bloccati manualmente
BLACKLIST_IPS = set([
    # "1.2.3.4",
])

# IP sempre consentiti (es. il tuo IP di casa/lavoro)
WHITELIST_IPS = set([
    "127.0.0.1",
])

# Limiti Rate Limiting: max richieste per finestra di tempo (in secondi)
MAX_REQUESTS_PER_WINDOW = 35 
RATE_LIMIT_WINDOW = 60 # 60 secondi

# Struttura per tracciare le richieste degli IP in memoria
ip_tracker = defaultdict(list)

# Pattern di attacco comuni (SQLi, XSS, Path Traversal, Command Injection)
ATTACK_PATTERNS = [
    r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|alter\s+table)", # SQLi
    r"(?i)(<script>|javascript:|onerror\s*=|onload\s*=|document\.cookie)",                            # XSS
    r"(\.\./|\.\.\\|/etc/passwd|c:\\windows)",                                                          # Path Traversal
    r"(?i)(exec\s*\(|eval\s*\(|system\s*\(|cmd\.exe|/bin/sh|/bin/bash)"                                  # Command Exec
]

# -------------------------------------------------------------------
# FUNZIONI DI VERIFICA
# -------------------------------------------------------------------

def get_client_ip():
    """Recupera l'IP reale del client gestendo anche eventuali proxy (es. Render/Cloudflare)."""
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip = request.remote_addr
    return ip or "0.0.0.0"

def is_payload_malicious(text):
    """Analizza il testo per verificare se contiene firme di attacchi noti."""
    if not text:
        return False
    for pattern in ATTACK_PATTERNS:
        if re.search(pattern, str(text)):
            return True
    return False

def check_rate_limit(client_ip):
    """Controlla se l'IP ha superato la soglia di richieste consentite."""
    now = time.time()
    # Pulisce le vecchie richieste fuori dalla finestra temporale
    ip_tracker[client_ip] = [t for t in ip_tracker[client_ip] if now - t < RATE_LIMIT_WINDOW]
    
    if len(ip_tracker[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
        return False
    
    ip_tracker[client_ip].append(now)
    return True

# -------------------------------------------------------------------
# MIDDLEWARE PRINCIPALE
# -------------------------------------------------------------------

def init_firewall(app):
    """Inizializza il firewall applicandolo a tutte le rotte di Flask."""

    @app.before_request
    def run_firewall_checks():
        client_ip = get_client_ip()

        # 1. Bypassa i controlli se l'IP è in Whitelist
        if client_ip in WHITELIST_IPS:
            return

        # 2. Controllo Blacklist
        if client_ip in BLACKLIST_IPS:
            print(f"🚨 [FIREWALL] IP Bloccato (In Blacklist): {client_ip}")
            abort(403, description="Accesso negato dal Firewall di sistema.")

        # 3. Controllo Rate Limiting (DoS Protection)
        if not check_rate_limit(client_ip):
            print(f"⚠️ [FIREWALL] Rate Limit Superato da IP: {client_ip}")
            abort(429, description="Troppe richieste inviate. Riprova tra un minuto.")

        # 4. Controllo Parametri URL (Query String)
        query_string = request.query_string.decode('utf-8', errors='ignore')
        if is_payload_malicious(query_string):
            print(f"🚨 [FIREWALL] Attacco Rilevato nell'URL da {client_ip}: {query_string}")
            abort(400, description="Richiesta bloccata: rilevati caratteri o comandi non consentiti.")

        # 5. Controllo Dati Form (POST / PUT)
        if request.method in ['POST', 'PUT']:
            for key, value in request.form.items():
                if is_payload_malicious(value):
                    print(f"🚨 [FIREWALL] Attacco Rilevato nel campo '{key}' da {client_ip}: {value}")
                    abort(400, description="Payload non valido rilevato dal Firewall.")

    @app.after_request
    def set_security_headers(response):
        """Aggiunge header di sicurezza HTTP a ogni risposta inviata."""
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response
