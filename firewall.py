import re
import time
from collections import defaultdict
from flask import request, abort

WHITELIST_IPS = set(["127.0.0.1"])
STATIC_BLACKLIST_IPS = set()

MAX_REQUESTS_PER_WINDOW = 40
RATE_LIMIT_WINDOW = 60
MAX_VIOLATIONS_BEFORE_BAN = 3
BAN_DURATION_SECONDS = 3600

ip_tracker = defaultdict(list)
ip_violations = defaultdict(int)
banned_ips = {}

MALICIOUS_USER_AGENTS = [
    r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|hydra|burp|zaproxy|acunetix|havij|netsparker|openvas|nessus)"
]

ATTACK_PATTERNS = [
    r"(?i)(union\s+(all\s+)?select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+database|drop\s+table|alter\s+table|update\s+.*\s+set|exec\s*\(|sp_executesql)",
    r"(?i)(information_schema|sys\.tables|sys\.objects|pg_catalog|benchmark\s*\(|sleep\s*\(|waitfor\s+delay)",
    r"(--|#|/\*|\*/|;\s*SELECT|;\s*DELETE|;\s*DROP)",
    r"(?i)(<script[^>]*>|javascript:|vbscript:|onload\s*=|onerror\s*=|onclick\s*=|onmouseover\s*=|eval\s*\(|expression\s*\(|document\.cookie|document\.location)",
    r"(?i)(<iframe|<object|<embed|<applet|<svg[^>]*onload)",
    r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self/environ|c:\\windows|c:\\system32)",
    r"(?i)(php://filter|php://input|data://text/plain|expect://)",
    r"(?i)(system\s*\(|passthru\s*\(|shell_exec\s*\(|exec\s*\(|popen|proc_open|curl_exec|eval\s*\()",
    r"(?i)(file://|gopher://|dict://|ldap://)"
]

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or "0.0.0.0"

def is_payload_malicious(text):
    if not text:
        return False
    for pattern in ATTACK_PATTERNS:
        if re.search(pattern, str(text)):
            return True
    return False

def is_user_agent_blocked(ua):
    if not ua:
        return False
    for pattern in MALICIOUS_USER_AGENTS:
        if re.search(pattern, ua):
            return True
    return False

def check_ban_status(ip):
    if ip in banned_ips:
        if time.time() < banned_ips[ip]:
            return True
        else:
            del banned_ips[ip]
            if ip in ip_violations:
                del ip_violations[ip]
    return False

def trigger_ban(ip):
    banned_ips[ip] = time.time() + BAN_DURATION_SECONDS
    print(f"🚨 [FIREWALL JAIL] IP {ip} BANNATO PER 1 ORA.")

def check_rate_limit(client_ip):
    now = time.time()
    ip_tracker[client_ip] = [t for t in ip_tracker[client_ip] if now - t < RATE_LIMIT_WINDOW]
    if len(ip_tracker[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
        return False
    ip_tracker[client_ip].append(now)
    return True

def init_firewall(app):
    @app.before_request
    def run_advanced_waf():
        client_ip = get_client_ip()
        if client_ip in WHITELIST_IPS:
            return
        if client_ip in STATIC_BLACKLIST_IPS or check_ban_status(client_ip):
            abort(403, description="Accesso Negato: IP Sospetto o Bannato.")
        if is_user_agent_blocked(request.headers.get('User-Agent', '')):
            abort(403, description="Accesso negato: Scanner non autorizzato.")
        if not check_rate_limit(client_ip):
            abort(429, description="Troppe richieste. Riprova più tardi.")

        query_str = request.query_string.decode('utf-8', errors='ignore')
        if is_payload_malicious(query_str):
            ip_violations[client_ip] += 1
            if ip_violations[client_ip] >= MAX_VIOLATIONS_BEFORE_BAN:
                trigger_ban(client_ip)
            abort(400, description="Richiesta bloccata dal Firewall avanzato.")

        if request.method in ['POST', 'PUT']:
            for key, val in request.form.items():
                if is_payload_malicious(val):
                    ip_violations[client_ip] += 1
                    if ip_violations[client_ip] >= MAX_VIOLATIONS_BEFORE_BAN:
                        trigger_ban(client_ip)
                    abort(400, description="Payload dannoso rilevato.")

    @app.after_request
    def apply_security_headers(response):
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval';"
        return response
