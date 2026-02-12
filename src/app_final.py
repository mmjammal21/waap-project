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
# استخدام قيم افتراضية للـ Local لضمان عدم توقف الكود إذا لم يجد ملف .env
APP_SECRET_KEY = os.getenv("APP_SECRET_KEY", "Malik_Secure_2026")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

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
    # تحميل الموديل الهجين النهائي (V7 - Balanced Edition)
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

    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) >= 5: # تم التعديل لتوافق تنسيق الـ log الجديد
                    entry = {
                        "time": parts[0],
                        "ip": parts[1],
                        "url": parts[2],
                        "threat": parts[3],
                        "action": parts[4]
                    }
                    if entry['action'] == "BLOCK": stats['BLOCK'] += 1
                    else: stats['ALLOW'] += 1

                    if "AI" in entry['threat']: stats['AI'] += 1
                    elif "SQL" in entry['threat']: stats['SQLi'] += 1
                    elif "XSS" in entry['threat']: stats['XSS'] += 1
                    elif "DDoS" in entry['threat']: stats['DDoS'] += 1
                    
                    all_logs.insert(0, entry)
    except: pass
    
    return stats, all_logs[:limit] if limit else all_logs

# ==========================================================
# 🛡️ WAAP Security Pipeline
# ==========================================================
def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

def log_event(ip, url, threat_type, action):
    t = datetime.now(timezone.utc) + timedelta(hours=3) # توقيت الأردن
    timestamp = t.strftime("%Y-%m-%d %H:%M:%S")
    # تنسيق موحد لضمان قراءة السجلات في الداشبورد
    logger.info(f"{timestamp}|{ip}|{url}|{threat_type}|{action}")

def extract_features(path, query, body):
    """
    التعديل الجوهري: نقوم بفحص المسار والمعاملات فقط 
    ونتجاهل اسم الدومين (Render URL) لمنع الحظر الخاطئ.
    """
    features = {col: 0 for col in model_columns}
    # نركز فقط على محتوى الطلب
    text = (path + " " + query + " " + body).lower()
    payload_len = len(text) if len(text) > 0 else 1
    
    # تحسين استخراج الميزات لصيد هجمات SQLi و XSS
    spec_chars = len(re.findall(r"[^a-zA-Z0-9\s]", text))
    sql_k = len(re.findall(r"(union|select|insert|drop|--|#|'|\"|%27|%23|or\s+1=1|admin')", text))
    xss_k = len(re.findall(r"(<|>|script|alert|onerror|onload|iframe|javascript:|%3c|%3e)", text))

    features['url_length'] = len(path)
    features['sql_keywords'] = sql_k
    features['xss_keywords'] = xss_k
    features['special_chars'] = spec_chars
    features['char_complexity'] = spec_chars / payload_len
    # معادلة الكثافة المحدثة (Code Density) لزيادة الحساسية للهجمات الحقيقية
    features['code_density'] = (sql_k * 2.5 + xss_k * 2.5) / payload_len
    
    return pd.DataFrame([features])

@app.before_request
def waap_pipeline():
    # استثناء الملفات الثابتة لسرعة الأداء
    if request.path.startswith('/static') or request.path == '/favicon.ico' or request.path == '/blocked':
        return

    ip = get_client_ip()
    path = request.path
    query = unquote(request.query_string.decode())
    body = request.get_data(as_text=True) or ""
    
    is_admin = session.get('role') == 'admin'

    # 1. Rate Limiting (Redis)
    if not is_admin:
        try:
            req_count = r.incr(ip)
            if req_count == 1: r.expire(ip, 60)
            if req_count > 100:
                log_event(ip, path, "DDoS Limit", "BLOCK")
                return render_template('blocked.html'), 429
        except: pass

    # 2. Signature Detection (WAF Layer - Fast Check)
    full_text = (path + " " + query + " " + body).lower()
    patterns = {
        "SQLi": r"(\bunion\b.*\bselect\b|' or 1=1|' or '1'='1'|admin'\s*--|--|#)",
        "XSS": r"(<script>|alert\(|onerror=|onload=)",
        "LFI": r"(\.\./|\.\.\\|/etc/passwd|/bin/sh)"
    }
    for name, pat in patterns.items():
        if re.search(pat, full_text):
            log_event(ip, path, f"{name} Attack", "BLOCK")
            return render_template('blocked.html'), 403

    # 3. AI Detection (V7 - Deep Analysis)
    try:
        # فحص الطلب عبر الموديل
        input_df = extract_features(path, query, body).reindex(columns=model_columns, fill_value=0)
        pred = rf_model.predict(input_df)[0]
        label = label_encoder.inverse_transform([pred])[0]
        
        # إذا كان التصنيف ليس 'Benign' (سليم)
        if label != 'Benign':
            log_event(ip, path, f"AI {label}", "BLOCK")
            return render_template('blocked.html'), 403
        else:
            # تسجيل الطلبات التي تحتوي على بارامترات فقط لتقليل الضوضاء في السجلات
            if query or body:
                log_event(ip, path, "Clean Request", "ALLOW")
                
    except Exception as e:
        logger.error(f"AI prediction error: {e}")

# ==========================================================
# 🌐 Routes
# ==========================================================
@app.route('/')
def index():
    if 'user' in session:
        if session.get('role') == 'admin': return redirect(url_for('dashboard'))
        return render_template('home.html', user=session['user'], ip=get_client_ip())
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('user', '').strip()
        pwd = request.form.get('pass', '').strip()
        
        if user == 'admin' and pwd == '123':
            session['user'], session['role'] = user, 'admin'
            log_event(get_client_ip(), "/login", "Admin Login", "ALLOW")
            return redirect(url_for('dashboard'))
        elif user == 'user' and pwd == '123':
            session['user'], session['role'] = user, 'user'
            log_event(get_client_ip(), "/login", "User Login", "ALLOW")
            return redirect(url_for('index'))
            
        return render_template('login.html', error="Invalid Credentials")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if session.get('role') != 'admin': return redirect(url_for('login'))
    stats, recent_logs = parse_waap_logs(limit=15)
    return render_template('dashboard.html', stats=stats, logs=recent_logs)

@app.route('/blocked')
def blocked():
    return render_template('blocked.html'), 403

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ==========================================================
# 🚀 Execution
# ==========================================================
if __name__ == "__main__":
    # استخدام المنفذ من البيئة المحيطة (للتوافق مع Render)
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
