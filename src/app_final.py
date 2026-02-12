import os
import re
import time
import pickle
import redis
import numpy as np
from datetime import datetime
from flask import Flask, request, redirect, render_template, abort

# ===============================
# CONFIGURATION
# ===============================

MODEL_PATH = "waap_model.pkl"
LOG_FILE = "waap_logs.txt"

RATE_LIMIT = 100          # max requests per window
RATE_WINDOW = 60          # seconds
AI_BASE_THRESHOLD = 0.75  # Base AI confidence threshold

SYSTEM_PATHS = [
    '/static',
    '/favicon.ico',
    '/blocked',
    '/dashboard',
    '/logs'
]

# ===============================
# INIT
# ===============================

app = Flask(__name__)

# Load model
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# Redis connection
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    password=os.getenv("REDIS_PASSWORD", None),
    decode_responses=True
)

# ===============================
# UTILITY FUNCTIONS
# ===============================

def log_event(ip, url, threat, action):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()}|{ip}|{url}|{threat}|{action}\n")


def rate_limit(ip):
    key = f"rate:{ip}"
    count = redis_client.get(key)

    if count is None:
        redis_client.setex(key, RATE_WINDOW, 1)
        return False

    if int(count) >= RATE_LIMIT:
        return True

    redis_client.incr(key)
    return False


def extract_features(payload):
    payload_len = len(payload)
    special_chars = len(re.findall(r'[^\w]', payload))
    sql_k = len(re.findall(r'\b(select|union|insert|drop|or|and)\b', payload, re.I))
    xss_k = len(re.findall(r'<script|alert\(|onerror=|javascript:', payload, re.I))

    if payload_len == 0:
        payload_len = 1

    char_complexity = special_chars / payload_len
    code_density = (sql_k * 2 + xss_k * 2) / payload_len

    return np.array([[payload_len, char_complexity, code_density]])


def adaptive_threshold(ip):
    """
    Dynamic threshold adjustment:
    - If IP has many recent suspicious attempts → lower threshold
    """
    suspicious_key = f"suspicious:{ip}"
    attempts = redis_client.get(suspicious_key)

    if attempts is None:
        return AI_BASE_THRESHOLD

    attempts = int(attempts)

    if attempts > 10:
        return 0.60  # more strict
    elif attempts > 5:
        return 0.68
    else:
        return AI_BASE_THRESHOLD


def mark_suspicious(ip):
    key = f"suspicious:{ip}"
    if redis_client.get(key) is None:
        redis_client.setex(key, 300, 1)
    else:
        redis_client.incr(key)


# ===============================
# SIGNATURE ENGINE
# ===============================

patterns = {
    "SQLi": r"(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|' or 1=1|--|#|\bdrop\b|\binsert\b)",
    "XSS": r"(<script.*?>.*?</script>|alert\(|onerror=|javascript:)",
    "LFI": r"(\.\./|\.\.\\|/etc/passwd)"
}

def signature_detect(payload):
    for name, pattern in patterns.items():
        if re.search(pattern, payload, re.I):
            return name
    return None


# ===============================
# WAAP PIPELINE
# ===============================

@app.before_request
def waap_pipeline():

    if any(request.path.startswith(p) for p in SYSTEM_PATHS):
        return

    ip = request.remote_addr
    payload = request.query_string.decode() + str(request.form)

    # Rate limiting
    if rate_limit(ip):
        log_event(ip, request.path, "DDoS", "BLOCK")
        abort(403)

    # Signature detection
    sig = signature_detect(payload)
    if sig:
        mark_suspicious(ip)
        log_event(ip, request.path, f"{sig}_Attack", "BLOCK")
        abort(403)

    # AI detection
    features = extract_features(payload)
    proba = model.predict_proba(features)[0][1]

    threshold = adaptive_threshold(ip)

    if proba >= threshold:
        mark_suspicious(ip)
        log_event(ip, request.path, f"AI_Attack({round(proba,2)})", "BLOCK")
        abort(403)

    # Log only real user paths
    if request.path not in ['/dashboard', '/logs']:
        log_event(ip, request.path, "NORMAL", "ALLOW")


# ===============================
# ROUTES
# ===============================

@app.route("/")
def home():
    return "WAAP System Running"


@app.route("/blocked")
def blocked():
    return "Request Blocked", 403


@app.route("/dashboard")
def dashboard():
    stats, logs = parse_waap_logs()
    return {
        "stats": stats,
        "recent_logs": logs[:20]
    }


# ===============================
# LOG PARSER
# ===============================

def parse_waap_logs(limit=None):

    stats = {
        'AI': 0,
        'SQLi': 0,
        'XSS': 0,
        'DDoS': 0,
        'ALLOW': 0,
        'BLOCK': 0
    }

    all_logs = []

    if not os.path.exists(LOG_FILE):
        return stats, all_logs

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

        for line in lines:
            parts = line.strip().split("|")
            if len(parts) != 5:
                continue

            entry = {
                "time": parts[0],
                "ip": parts[1],
                "url": parts[2],
                "threat": parts[3],
                "action": parts[4]
            }

            if entry['action'] == "BLOCK":
                stats['BLOCK'] += 1
            elif entry['action'] == "ALLOW":
                stats['ALLOW'] += 1

            threat = entry['threat']

            if "SQL" in threat:
                stats['SQLi'] += 1
            elif "XSS" in threat:
                stats['XSS'] += 1
            elif "DDoS" in threat:
                stats['DDoS'] += 1
            elif "AI" in threat:
                stats['AI'] += 1

            all_logs.insert(0, entry)

    return stats, all_logs[:limit] if limit else all_logs


# ===============================
# MAIN
# ===============================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
