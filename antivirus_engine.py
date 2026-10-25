import hashlib
import math
import re

KNOWN_MALICIOUS_HASHES = set([
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
])

HEURISTIC_PATTERNS = [
    r"(?i)(eval\s*\(base64_decode|assert\s*\(|passthru\s*\(|shell_exec\s*\()",
    r"(?i)(powershell\s+.*-enc|cmd\.exe\s+/c|wscript\.shell|certutil\s+-urlcache)",
    r"(?i)(192\.168\.\d+\.\d+|https?://[^\s]+\.(ru|cn|top)/[^\s]+\.exe)",
    r"(?i)(bitcoin|monero|wallet|ransom|decrypt_files|your_files_are_encrypted)"
]

def calculate_sha256(file_bytes):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_bytes)
    return sha256_hash.hexdigest()

def calculate_entropy(file_bytes):
    if not file_bytes:
        return 0.0
    entropy = 0.0
    data_len = len(file_bytes)
    byte_counts = [0] * 256
    for b in file_bytes:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p_x = float(count) / data_len
            entropy -= p_x * math.log2(p_x)
    return entropy

def check_file_header(file_bytes):
    if len(file_bytes) < 4:
        return "Sconosciuto"
    header = file_bytes[:4]
    if header.startswith(b'\x4d\x5a'):
        return "Eseguibile Windows (PE / .exe)"
    elif header.startswith(b'\x7f\x45\x4c\x46'):
        return "Eseguibile Linux (ELF)"
    elif header.startswith(b'\x25\x50\x44\x46'):
        return "Documento PDF"
    elif header.startswith(b'\x50\x4b\x03\x04'):
        return "Archivio Compresso (ZIP / Office Doc)"
    elif header.startswith(b'\xff\xd8\xff'):
        return "Immagine JPEG"
    elif header.startswith(b'\x89\x50\x4e\x47'):
        return "Immagine PNG"
    return "File Generico / Sconosciuto"

def scan_payload(target_input):
    if isinstance(target_input, str):
        content_bytes = target_input.encode('utf-8', errors='ignore')
        is_text = True
    else:
        content_bytes = target_input
        is_text = False

    file_hash = calculate_sha256(content_bytes)
    if file_hash in KNOWN_MALICIOUS_HASHES:
        return {
            "status": "INFETTO (CRITICAL)",
            "risk_score": 100,
            "file_type": check_file_header(content_bytes),
            "sha256": file_hash,
            "entropy": round(calculate_entropy(content_bytes), 2),
            "details": f"Corrispondenza esatta trovata nel database firme malware (SHA-256: {file_hash})"
        }

    entropy = calculate_entropy(content_bytes)
    entropy_warning = entropy > 7.2 and not is_text

    text_content = content_bytes.decode('utf-8', errors='ignore')
    matches = [p for p in HEURISTIC_PATTERNS if re.search(p, text_content)]

    risk_score = 0
    if matches:
        risk_score += len(matches) * 35
    if entropy_warning:
        risk_score += 40
    if "Eseguibile Windows" in check_file_header(content_bytes) and not is_text:
        risk_score += 15

    risk_score = min(risk_score, 100)
    file_type = check_file_header(content_bytes)

    if risk_score >= 70:
        status = "MALIGNO / INFETTO (ALTO RISCHIO)"
    elif risk_score >= 35:
        status = "SOSPETTO (ATTENZIONE RICHIESTA)"
    else:
        status = "PULITO (SICURO)"

    return {
        "status": status,
        "risk_score": risk_score,
        "file_type": file_type,
        "sha256": file_hash,
        "entropy": round(entropy, 2),
        "details": f"Analisi completata. Tipo file: {file_type}. Entropia: {round(entropy, 2)}. Pattern sospetti: {len(matches)}."
      }
