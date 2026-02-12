import os
import re
import logging
import joblib
import redis
import numpy as np
import pandas as pd

from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from urllib.parse import unquote
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# ==========================================================
# 🔐 Environment Configuration
# ==========================================================
load_dotenv()
APP_SECRET_KEY = os.getenv("APP_SECRET_KEY")
REDIS_URL = os.getenv("REDIS_URL")

if not APP_SECRET_KEY or not REDIS_URL:
    raise RuntimeError("APP_SECRET_KEY or REDIS_URL not set in .env")

# إعدادات ملف السجلات وتنسيقها لتتوافق مع الداشبورد
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
try:
    r = redis.from_url(REDIS_URL, decode_responses=True)
    r.ping()
    logger.info("✅ Connected to Redis")
except Exception as e:
    logger.error(f"❌ Redis Error: {e}")

# ==========================================================
# 📁 Model Paths & Loading
# ==========================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, '../data')

try:
    # تحميل الموديل الهجين النهائي (تحديث المسمى لـ V7 - Balanced Edition)
    rf_model = joblib.load(os.path.join(DATA_DIR, 'waap_model.pkl'))
    model_columns = joblib.load(os.path.join(DATA_DIR, 'model_features.pkl'))
    # تم تعديل السطر أدناه ليعكس دقة النسخة السابعة 91.30% كما في صورتك الأخيرة
    logger.info("✅ AI Model Ready (Hybrid Version V7 - Balanced Edition 91.30%)")
except Exception as e:
    logger.error(f"❌ Model Load Error: {e}")

# ==========================================================
# 📊 Dashboard & Logs Logic
# ==========================================================
def parse_waap_logs(limit=None):
    stats = {'AI': 0, 'SQLi': 0, 'XSS': 0, 'DDoS': 0, 'ALLOW': 0, 'BLOCK': 0}
    all_logs = []
    if not os.path.exists(LOG_FILE): return stats, all_logs

    with open(LOG_FILE, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            # الحفاظ على تصحيح الأعمدة الذي وضعته أنت (القرار في العمود 6)
            if len(parts) >= 7:
                entry = {
                    "time": parts[2],
                    "ip": parts[3],
                    "url": parts[4],
                    "threat": parts[5],
                    "action": parts[6]
                }
                if entry['action'] == "BLOCK": stats['BLOCK'] += 1
                else: stats['ALLOW'] += 1

                if "AI" in entry['threat']: stats['AI'] += 1
                elif "SQL" in entry['threat']: stats['SQLi'] += 1
                elif "XSS" in entry['threat']: stats['XSS'] += 1
                elif "DDoS" in entry['threat']: stats['DDoS'] += 1
                
                all_logs.insert(0, entry)
    
    return stats, all_logs[:limit] if limit else all_logs

# ==========================================================
# 🛡️ WAAP Security Pipeline
# ==========================================================
def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

def log_event(ip, url, threat_type, action):
    # توقيت الأردن (UTC+3) كما هو في كودك
    t = datetime.now(timezone.utc) + timedelta(hours=3)
    timestamp = t.strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"{timestamp}|{ip}|{url}|{threat_type}|{action}")

def extract_features(url, body):
    features = {col: 0 for col in model_columns}
    text = (url + " " + body).lower()
    url_len = len(url) if len(url) > 0 else 1
    
    spec_chars = len(re.findall(r"[^a-zA-Z0-9\s]", text))
    sql_k = len(re.findall(r"(union|select|insert|drop|--|#|/\*|'|\"|%27|%23)", text))
    xss_k = len(re.findall(r"(<|>|script|alert|onerror|onload|iframe|javascript:|%3c|%3e)", text))

    features['url_length'] = url_len
    features['sql_keywords'] = sql_k
    features['xss_keywords'] = xss_k
    features['special_chars'] = spec_chars
    features['char_complexity'] = spec_chars / url_len
    features['code_density'] = (sql_k + xss_k) / url_len
    
    return pd.DataFrame([features])

@app.before_request
def waap_pipeline():
    if request.path.startswith('/static') or request.path == '/favicon.ico':
        return

    ip, url = get_client_ip(), unquote(request.full_path)
    is_admin = session.get('role') == 'admin'

    # 1. Rate Limiting (Redis) - كودك كما هو
    if not is_admin:
        try:
            req_count = r.incr(ip)
            if req_count == 1: r.expire(ip, 60)
            if req_count > 100:
                log_event(ip, request.path, "DDoS Limit", "BLOCK")
                return render_template('blocked.html'), 429
        except: pass

    # 2. Signature Detection (WAF Layer) - كودك كما هو
    body = request.get_data(as_text=True) or ""
    full_text = (url + " " + body).lower()
    patterns = {
        "SQLi": r"(\bunion\b.*\bselect\b|' or 1=1|admin'\s*--)",
        "XSS": r"(<script>|alert\(|onerror=|onload=)",
        "LFI": r"(\.\./|\.\.\\|/etc/passwd|/bin/sh)"
    }
    for name, pat in patterns.items():
        if re.search(pat, full_text):
            log_event(ip, url, f"{name} Attack", "BLOCK")
            return render_template('blocked.html'), 403

    # 3. AI Detection (V7 - Logic)
    try:
        # القائمة البيضاء: أضفت لها '/' لمنع الحظر التلقائي عند الدخول للرابط الرئيسي
        whitelist = ['/', '/login', '/dashboard', '/logout', '/static', '/logs']
        if any(request.path == path or request.path.startswith(path) for path in whitelist):
            return 

        input_df = extract_features(url, body).reindex(columns=model_columns, fill_value=0)
        pred = rf_model.predict(input_df)[0]
        
        # التوافق مع V7: Benign=0, Network=1, Web=2 كما في صورتك
        safe_classes = [0] 
        
        if int(pred) not in safe_classes:
            threat_name = "Network Attack" if int(pred) == 1 else "Web Attack"
            log_event(ip, url, f"AI {threat_name} (Class {pred})", "BLOCK")
            return render_template('blocked.html'), 403
        else:
            log_event(ip, url, f"AI Safe (Class {pred})", "ALLOW")
            
    except Exception as e:
        logger.error(f"AI prediction error: {e}")

# ==========================================================
# 🌐 Routes - كودك كما هو دون أي تغيير
# ==========================================================
@app.route('/')
def index():
    if 'user' in session:
        if session['role'] == 'admin': return redirect(url_for('dashboard'))
        return render_template('home.html', user=session['user'], ip=get_client_ip())
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user, pwd = request.form.get('user', '').strip(), request.form.get('pass', '').strip()
        if user == 'admin' and pwd == '123':
            session['user'], session['role'] = user, 'admin'
            log_event(get_client_ip(), "/login", "Admin Login", "ALLOW")
            return redirect(url_for('dashboard'))
        elif user == 'user' and pwd == '123':
            session['user'], session['role'] = user, 'user'
            log_event(get_client_ip(), "/login", "User Login", "ALLOW")
            return render_template('home.html', user=user, ip=get_client_ip())
        return render_template('login.html', error="Invalid Credentials")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if session.get('role') != 'admin': return redirect(url_for('login'))
    stats, recent_logs = parse_waap_logs(limit=15)
    return render_template('dashboard.html', stats=stats, logs=recent_logs)

@app.route('/logs')
def view_logs():
    if session.get('role') != 'admin': return redirect(url_for('login'))
    _, all_logs = parse_waap_logs()
    return render_template('logs.html', logs=all_logs)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ==========================================================
# 🚀 Execution
# ==========================================================
if __name__ == "__main__":
    # ملاحظة: تم تغيير host لـ 0.0.0.0 ليعمل مع Docker بنجاح
    app.run(debug=True, host='0.0.0.0', port=5000)
