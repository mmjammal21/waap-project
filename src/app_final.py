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
APP_SECRET_KEY = os.getenv("APP_SECRET_KEY", "Malik_Secure_2026")
REDIS_URL = os.getenv("REDIS_URL")

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
    if REDIS_URL:
        r = redis.from_url(REDIS_URL, decode_responses=True)
        r.ping()
        logger.info("✅ Connected to Redis")
    else:
        logger.warning("⚠️ REDIS_URL not set, Rate Limiting disabled.")
except Exception as e:
    logger.error(f"❌ Redis Error: {e}")

# ==========================================================
# 📁 Model Paths & Loading
# ==========================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, '../data')

try:
    rf_model = joblib.load(os.path.join(DATA_DIR, 'waap_model.pkl'))
    model_columns = joblib.load(os.path.join(DATA_DIR, 'model_features.pkl'))
    label_encoder = joblib.load(os.path.join(DATA_DIR, 'label_encoder.pkl'))
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
            if len(parts) >= 5: 
                entry = {
                    "time": parts[0],
                    "ip": parts[1] if len(parts)>1 else "0.0.0.0",
                    "url": parts[2] if len(parts)>2 else "/",
                    "threat": parts[3] if len(parts)>3 else "Unknown",
                    "action": parts[4] if len(parts)>4 else "ALLOW"
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
    t = datetime.now(timezone.utc) + timedelta(hours=3)
    timestamp = t.strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"{timestamp}|{ip}|{url}|{threat_type}|{action}")

def extract_features(path, query, body):
    features = {col: 0 for col in model_columns}
    text = (path + " " + query + " " + body).lower()
    payload_len = len(text) if len(text) > 0 else 1
    
    spec_chars = len(re.findall(r"[^a-zA-Z0-9\s]", text))
    sql_k = len(re.findall(r"(union|select|insert|drop|--|#|/\*|'|\"|or|and|1=1|1=0)", text))
    xss_k = len(re.findall(r"(<|>|script|alert|onerror|onload|iframe|javascript:)", text))

    features['url_length'] = len(path)
    features['sql_keywords'] = sql_k
    features['xss_keywords'] = xss_k
    features['special_chars'] = spec_chars
    # حساب التعقيد الرياضي لضمان الدقة
    # $$ \text{char\_complexity} = \frac{\text{special\_chars}}{\text{payload\_len}} $$
    features['char_complexity'] = spec_chars / payload_len
    features['code_density'] = (sql_k * 2.5 + xss_k * 2.5) / payload_len
    
    return pd.DataFrame([features])

@app.before_request
def waap_pipeline():
    # 1. استثناء الملفات الثابتة وصفحات النظام الأساسية
    if request.path.startswith('/static') or request.path in ['/favicon.ico', '/blocked', '/logout']:
        return

    # 2. الحل النهائي للحظر التلقائي (Image 26): السماح بطلبات GET لصفحات الدخول
    # هذا يضمن ظهور صفحة الـ Login دائماً للمستخدم الطبيعي
    if request.method == 'GET' and request.path in ['/', '/login']:
        return

    ip, url_path = get_client_ip(), request.path
    query = request.query_string.decode()
    body = request.get_data(as_text=True) or ""
    
    # 3. Rate Limiting (Redis)
    is_admin = session.get('role') == 'admin'
    if not is_admin:
        try:
            req_count = r.incr(ip)
            if req_count == 1: r.expire(ip, 60)
            if req_count > 100:
                log_event(ip, url_path, "DDoS Limit", "BLOCK")
                return render_template('blocked.html'), 429
        except: pass

    # 4. Signature Detection (WAF Layer)
    full_text = (unquote(request.full_path) + " " + body).lower()
    patterns = {
        "SQLi": r"(\bunion\b.*\bselect\b|' or 1=1|' or '1'='1'|admin'\s*--|--|#)",
        "XSS": r"(<script>|alert\(|onerror=|onload=)",
        "LFI": r"(\.\./|\.\.\\|/etc/passwd|/bin/sh)"
    }
    for name, pat in patterns.items():
        if re.search(pat, full_text):
            log_event(ip, url_path, f"{name} Attack", "BLOCK")
            return render_template('blocked.html'), 403

    # 5. AI Detection (V7) - فحص ذكي للبيانات فقط
    try:
        # إذا كان الطلب لا يحتوي على أي بيانات، لا داعي للفحص (تجنب الحظر الخاطئ للدومين)
        if not query and not body:
            return

        input_df = extract_features(url_path, query, body).reindex(columns=model_columns, fill_value=0)
        pred = rf_model.predict(input_df)[0]
        
        # Benign=0 في موديل V7 المحدث
        if int(pred) != 0:
            threat_name = "Network Attack" if int(pred) == 1 else "Web Attack"
            log_event(ip, url_path, f"AI {threat_name}", "BLOCK")
            return render_template('blocked.html'), 403
            
    except Exception as e:
        logger.error(f"AI error: {e}")

# ==========================================================
# 🌐 Routes
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
        # التوافق مع HTML (Image 29): يقرأ user و pass
        user = (request.form.get('user') or request.form.get('identity') or "").strip()
        pwd = (request.form.get('pass') or request.form.get('access_key') or "").strip()
        
        logger.info(f"Attempting login for: {user}")

        if user == 'admin' and pwd == '123':
            session['user'], session['role'] = user, 'admin'
            log_event(get_client_ip(), "/login", "Admin Login", "ALLOW")
            return redirect(url_for('dashboard'))
        elif user == 'user' and pwd == '123':
            session['user'], session['role'] = user, 'user'
            log_event(get_client_ip(), "/login", "User Login", "ALLOW")
            return render_template('home.html', user=user, ip=get_client_ip())
        
        # إذا فشل الدخول (Image 27)
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

@app.route('/blocked')
def blocked():
    return render_template('blocked.html'), 403

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == "__main__":
    # التعديل لضمان العمل على Render و Localhost تلقائياً
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
