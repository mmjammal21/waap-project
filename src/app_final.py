import os
import re
import logging
import joblib
import redis
import pandas as pd

from flask import Flask, request, render_template, redirect, url_for, session
from urllib.parse import unquote
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# ==========================================================
# 🔐 Environment Configuration
# ==========================================================
load_dotenv()
APP_SECRET_KEY = os.getenv("APP_SECRET_KEY", "Malik_Secure_2026")
REDIS_URL = os.getenv("REDIS_URL")

LOG_FILE = "waap.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s|%(levelname)s|%(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("WAAP")

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY

# ==========================================================
# 🔴 Redis Connection
# ==========================================================
r = None
if REDIS_URL:
    try:
        r = redis.from_url(REDIS_URL, decode_responses=True)
        r.ping()
        logger.info("✅ Connected to Redis")
    except Exception as e:
        logger.error(f"❌ Redis Error: {e}")
else:
    logger.warning("⚠️ REDIS_URL not set, Rate Limiting disabled.")

# ==========================================================
# 📁 Model Loading
# ==========================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, '../data')

try:
    rf_model = joblib.load(os.path.join(DATA_DIR, 'waap_model.pkl'))
    model_columns = joblib.load(os.path.join(DATA_DIR, 'model_features.pkl'))
    logger.info("✅ AI Model Ready (V7 Balanced 91.30%)")
except Exception as e:
    logger.error(f"❌ Model Load Error: {e}")

# ==========================================================
# 📊 Log Parser
# ==========================================================
def parse_waap_logs(limit=None):
    stats = {'AI': 0, 'SQLi': 0, 'XSS': 0, 'DDoS': 0, 'ALLOW': 0, 'BLOCK': 0}
    logs = []

    if not os.path.exists(LOG_FILE):
        return stats, logs

    with open(LOG_FILE, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) == 5:
                entry = {
                    "time": parts[0],
                    "ip": parts[1],
                    "url": parts[2],
                    "threat": parts[3],
                    "action": parts[4]
                }

                if entry['action'] == "BLOCK":
                    stats['BLOCK'] += 1
                else:
                    stats['ALLOW'] += 1

                if "AI" in entry['threat']:
                    stats['AI'] += 1
                elif "SQL" in entry['threat']:
                    stats['SQLi'] += 1
                elif "XSS" in entry['threat']:
                    stats['XSS'] += 1
                elif "DDoS" in entry['threat']:
                    stats['DDoS'] += 1

                logs.insert(0, entry)

    return stats, logs[:limit] if limit else logs

# ==========================================================
# 🛡️ Helper Functions
# ==========================================================
def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

def log_event(ip, url, threat, action):
    t = datetime.now(timezone.utc) + timedelta(hours=3)
    timestamp = t.strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp}|{ip}|{url}|{threat}|{action}\n")

    logger.info(f"{timestamp}|{ip}|{url}|{threat}|{action}")

def extract_features(query, body):
    features = {col: 0 for col in model_columns}

    text = (query + " " + body).lower()
    payload_len = len(text) if len(text) > 0 else 1

    spec_chars = len(re.findall(r"[^a-zA-Z0-9\s]", text))
    sql_k = len(re.findall(r"(union|select|insert|drop|--|#|'|\"|or|and|1=1|1=0)", text))
    xss_k = len(re.findall(r"(<|>|script|alert|onerror|onload|iframe|javascript:)", text))

    features['url_length'] = len(query)
    features['sql_keywords'] = sql_k
    features['xss_keywords'] = xss_k
    features['special_chars'] = spec_chars
    features['char_complexity'] = spec_chars / payload_len
    features['code_density'] = (sql_k * 2.5 + xss_k * 2.5) / payload_len

    return pd.DataFrame([features])

# ==========================================================
# 🛡️ WAAP Pipeline (Fixed)
# ==========================================================
BLOCK_THRESHOLD = 0.98

@app.before_request
def waap_pipeline():

    safe_paths = ['/', '/login', '/blocked', '/logout']

    if request.path.startswith('/static') \
       or request.path.startswith('/favicon') \
       or request.path in safe_paths:
        return

    ip = get_client_ip()
    url_path = request.path
    query = request.query_string.decode()
    body = request.get_data(as_text=True) or ""

    # ---------------- Rate Limiting ----------------
    if r and session.get('role') != 'admin':
        try:
            req_count = r.incr(ip)
            if req_count == 1:
                r.expire(ip, 60)
            if req_count > 100:
                log_event(ip, url_path, "DDoS Limit", "BLOCK")
                return render_template('blocked.html'), 429
        except:
            pass

    # ---------------- Signature Detection ----------------
    scan_text = (unquote(query) + " " + body).lower()

    patterns = {
        "SQLi": r"(\bunion\b.*\bselect\b|' or 1=1|' or '1'='1'|--|#)",
        "XSS": r"(<script>|alert\(|onerror=|onload=)",
        "LFI": r"(\.\./|\.\.\\|/etc/passwd)"
    }

    for name, pat in patterns.items():
        if re.search(pat, scan_text):
            log_event(ip, url_path, f"{name} Attack", "BLOCK")
            return render_template('blocked.html'), 403

    # ---------------- AI Detection ----------------
    payload = (query + " " + body).strip()
    if not payload:
        return

    try:
        input_df = extract_features(query, body).reindex(columns=model_columns, fill_value=0)
        proba = rf_model.predict_proba(input_df)[0][1]

        if proba >= BLOCK_THRESHOLD:
            log_event(ip, url_path, "AI Web Attack", "BLOCK")
            return render_template('blocked.html'), 403

        if proba > 0.5:
            log_event(ip, url_path, "AI Suspicious", "ALLOW")

    except Exception as e:
        logger.error(f"AI error: {e}")

# ==========================================================
# 🌐 Routes
# ==========================================================
@app.route('/')
def index():
    if 'user' in session:
        if session['role'] == 'admin':
            return redirect(url_for('dashboard'))
        return render_template('home.html', user=session['user'], ip=get_client_ip())
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = (request.form.get('user') or "").strip()
        pwd = (request.form.get('pass') or "").strip()

        if user == 'admin' and pwd == '123':
            session['user'], session['role'] = user, 'admin'
            return redirect(url_for('dashboard'))

        elif user == 'user' and pwd == '123':
            session['user'], session['role'] = user, 'user'
            return render_template('home.html', user=user, ip=get_client_ip())

        return render_template('login.html', error="Invalid Credentials")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    stats, logs = parse_waap_logs(limit=15)
    return render_template('dashboard.html', stats=stats, logs=logs)

@app.route('/logs')
def view_logs():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    _, logs = parse_waap_logs()
    return render_template('logs.html', logs=logs)

@app.route('/blocked')
def blocked():
    return render_template('blocked.html'), 403

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ==========================================================
# 🚀 Run
# ==========================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
