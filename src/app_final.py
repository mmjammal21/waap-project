import os
import logging
import joblib  
import time
import re
import math
import pandas as pd
import numpy as np
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from collections import defaultdict, deque
from urllib.parse import unquote
from datetime import datetime, timedelta, timezone 
from pyngrok import ngrok 

# ==========================================================
# 📂 إعدادات المسارات (نظام كالي لينكس)
# ==========================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")

os.makedirs(LOG_DIR, exist_ok=True)
MODEL_PATH = os.path.join(DATA_DIR, 'waap_model.pkl')
LOG_FILE = os.path.join(LOG_DIR, "waap.log")

# --- 1. تحسين التيرمينال: إسكات السجلات المزعجة ---
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.getLogger('pyngrok').setLevel(logging.ERROR)

# --- 2. إعدادات الوقت الأردني (نظام 12 ساعة) ---
class JordanFormatter(logging.Formatter):
    def format(self, record):
        tz_jordan = timezone(timedelta(hours=3))
        dt = datetime.now(tz_jordan).strftime('%I:%M:%S %p')
        return f"[{dt}] | {record.msg}"

handler = logging.FileHandler(LOG_FILE)
# التنسيق الموحد للملف لسهولة القراءة برمجياً
handler.setFormatter(logging.Formatter("%(asctime)s|%(message)s"))
stream = logging.StreamHandler()
stream.setFormatter(JordanFormatter())

logging.basicConfig(level=logging.INFO, handlers=[handler, stream])

app = Flask(__name__)
app.secret_key = "WAAP_GATEWAY_PROJECT_2026_JUST"

# ==========================================================
# 🧠 تحميل محرك الذكاء الاصطناعي V8.0
# ==========================================================
try:
    model = joblib.load(MODEL_PATH)
    label_encoder = joblib.load(os.path.join(DATA_DIR, 'label_encoder.pkl'))
    model_columns = joblib.load(os.path.join(DATA_DIR, 'model_features.pkl'))
    logging.info(f"0.0.0.0 | SYSTEM_READY | AI_V8_ACTIVE")
except Exception as e:
    logging.error(f"0.0.0.0 | LOAD_ERROR | {e}")

# ==========================================================
# 🛠️ محرك الإحصائيات (الإصلاح: منطق الفرز الدقيق)
# ==========================================================
def get_live_data():
    stats = {'AI': 0, 'SQLi': 0, 'XSS': 0, 'DDoS': 0, 'ALLOW': 0, 'BLOCK': 0}
    security_events = [] 
    if not os.path.exists(LOG_FILE): return stats, []
    
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
            for line in lines:
                parts = line.strip().split('|')
                if len(parts) >= 4:
                    # تنظيف البيانات من الفراغات لضمان دقة المقارنة
                    ip_part = parts[1].strip()
                    threat_type = parts[2].strip()
                    action = parts[3].strip()
                    timestamp = parts[0].strip()

                    # تحديث العدادات الإجمالية
                    if action == "BLOCK":
                        stats['BLOCK'] += 1
                        if "SQL" in threat_type: stats['SQLi'] += 1
                        elif "XSS" in threat_type: stats['XSS'] += 1
                        elif "DDOS" in threat_type: stats['DDoS'] += 1
                        else: stats['AI'] += 1
                    elif action == "ALLOW":
                        stats['ALLOW'] += 1

                    # إضافة الهجمات فقط للجدول (تجاهل الرسائل النظامية والآمنة)
                    if threat_type not in ["SAFE_TRAFFIC", "SYSTEM_READY"] and "SUCCESS" not in threat_type:
                        security_events.append({
                            'time': timestamp,
                            'ip': ip_part,
                            'threat': threat_type,
                            'action': action
                        })
    except Exception as e:
        print(f"Read Error: {e}")
        
    return stats, security_events[-15:][::-1]

# ==========================================================
# 🛑 أنظمة الحماية (Signatures & DDoS)
# ==========================================================
def check_signatures(payload):
    sigs = [
        r"union.*select", r"etc/shadow", r"etc/passwd", r"script.*alert", 
        r"(\d+\s+OR\s+['\"]?\d+)", r"DROP\s+TABLE", r"\.\./\.\./",
        r"cat\s+/", r"config\\SAM", r"/etc/", r"/passwd"
    ]
    return any(re.search(sig, payload, re.I) for sig in sigs)

request_log = defaultdict(deque)
def is_rate_limited(ip):
    # مؤقتاً للمناقشة: خفّض الحد لـ 10 طلبات بدلاً من 100 لتفعيل الحظر بسرعة
    current_time = time.time()
    window = request_log[ip]
    while window and window[0] < current_time - 60: window.popleft()
    
    if len(window) >= 10: # حظر بعد 10 طلبات فقط للتجربة
        return True
    window.append(current_time)
    return False

# ==========================================================
# 🔍 استخراج ميزات AI
# ==========================================================
def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0: entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_features_v8(path, query, body):
    text = (path + " " + query + " " + body).lower().strip()
    url_len = max(len(text), 1)
    spec_chars = len(re.findall(r"[^a-zA-Z0-9\s]", text))
    sql_k = len(re.findall(r"(union|select|insert|drop|--|#|concat|where)", text))
    xss_k = len(re.findall(r"(<|>|script|alert|onerror|onload)", text))
    features = {
        'url_length': url_len, 'sql_keywords': sql_k, 'xss_keywords': xss_k,
        'special_chars': spec_chars, 'char_complexity': spec_chars / url_len,
        'code_density': (sql_k + xss_k) / url_len, 'entropy': calculate_entropy(text),
        'semicolon_count': text.count(';'), 'apostrophe_count': text.count("'"),
        'bracket_count': text.count('(') + text.count(')')
    }
    return pd.DataFrame([features])[model_columns]

# ==========================================================
# 🛡️ حارس الأمن (Middleware)
                                                     # ==========================================================
# 🛑 1. تحديث قائمة التوقيعات (ضعه مكان الدالة القديمة)
def check_signatures(payload):
    # قائمة توقيعات احترافية وشاملة (Comprehensive Blacklist)
    sigs = [
        # 1. SQL Injection: صيد ' OR '1'='1 بجميع أشكاله والتعليقات --
        r"(\'|\"|%27|%22)\s+(or|and)\s+([\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+)", 
        r"union.*select", r"select.*from", r"insert.*into", r"drop\s+table", r"\'\s*--", r"\"\s*--",
        
        # 2. XSS: صيد الأحداث (onerror, onload, onclick) والوسوم (svg, img, script)
        r"<script.*?>", r"alert\(", r"on\w+\s*=", r"<svg", r"<img", r"<iframe>", r"javascript:",
        
        # 3. LFI: صيد محاولات التنقل بين المجلدات
        r"\.\./", r"\.\.\\", r"etc/passwd", r"etc/shadow", r"/proc/self/"
    ]
    # الفحص بدون حساسية لحالة الأحرف (Ignore Case)
    return any(re.search(sig, payload, re.I) for sig in sigs)

@app.before_request
def security_check():
    if request.path in ['/health', '/blocked', '/logout', '/dashboard', '/logs', '/api/stats'] or request.path.startswith('/static/'):
        return

    ip = request.headers.get('X-Forwarded-For', request.remote_addr) or request.remote_addr
    query = unquote(request.query_string.decode())
    body = unquote(request.get_data(as_text=True))
    full_payload = (query + " " + body).lower()

    # 1. DDoS Check
    if is_rate_limited(ip):
        logging.info(f"{ip} | DDOS_ATTACK | BLOCK")
        return redirect(url_for('blocked'))

    # 2. حماية شاملة (لكل المسارات بما فيها الدخول)
    threat = "SAFE_TRAFFIC"
    is_malicious = False

    # فحص التوقيعات (Signature Detection)
    if check_signatures(full_payload):
        is_malicious = True
        if any(x in full_payload for x in ['etc/', 'passwd', '../']): threat = "LFI_ATTEMPT"
        elif any(x in full_payload for x in ['script', 'alert', 'onerror', 'onload', '<svg', '<img']): threat = "XSS_ATTACK"
        elif any(x in full_payload for x in ['union', 'select', 'or', '--']): threat = "SQL_INJECTION"
        else: threat = "MALICIOUS_REQUEST"

    # فحص الذكاء الاصطناعي كخط دفاع ثاني
    if not is_malicious:
        try:
            f_df = extract_features_v8(request.path, query, body)
            probs = model.predict_proba(f_df)[0]
            if (probs[1] + probs[2]) >= 0.70:
                is_malicious = True
                threat = "AI_ANOMALY"
        except: pass

    # القرار النهائي
    if is_malicious:
        logging.info(f"{ip} | {threat} | BLOCK")
        return redirect(url_for('blocked'))
    
    # تسجيل الدخول السليم فقط إذا لم يكن هناك تهديد
    if request.path in ['/', '/login'] and request.method == 'POST':
        return # نترك دالة الـ login تتعامل معه
# ==========================================================
# 🌐 المسارات والـ API
# ==========================================================
@app.route('/api/stats')
def api_stats():
    stats, logs_list = get_live_data()
    return jsonify({"stats": stats, "logs": logs_list})

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.form.get('user'), request.form.get('pass')
        ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        
        if (u == 'admin' or u == 'user') and p == 'Just@1999':
            logging.info(f"{ip} | {u.upper()}_SUCCESS | ALLOW")
            session['user'], session['role'] = u, ('Administrator' if u == 'admin' else 'Regular User')
            return redirect(url_for('dashboard' if u == 'admin' else 'home'))
        
        logging.info(f"{ip} | FAILED_LOGIN | BLOCK")
        return render_template('login.html', error="Invalid Credentials")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if session.get('user') != 'admin': return redirect(url_for('login'))
    stats, logs_list = get_live_data()
    return render_template('dashboard.html', user=session['user'], stats=stats, logs=logs_list)

@app.route('/logs')
def logs():
    if session.get('user') != 'admin': return redirect(url_for('login'))
    _, all_logs = get_live_data()
    return render_template('logs.html', logs=all_logs)

@app.route('/home')
def home():
    if 'user' not in session: return redirect(url_for('login'))
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    return render_template('home.html', user=session['user'], role=session['role'], ip=ip)

@app.route('/blocked')
def blocked(): return render_template('blocked.html'), 403

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    TOKEN = "3Aja1DPgYYdYi3ECctzdtmQQwUh_6w18eRDP51rE9Xto23c9a"
    ngrok.set_auth_token(TOKEN)
    try:
        public_url = ngrok.connect(addr="https://localhost:5000", proto="http", bind_tls=True).public_url
        print(f"\n🚀 SYSTEM LIVE: {public_url}\n")
    except Exception as e:
        print(f"⚠️ Ngrok Warning: {e}")
    
    cert_path = os.path.join(PROJECT_ROOT, 'nginx', 'nginx-selfsigned.crt')
    key_path = os.path.join(PROJECT_ROOT, 'nginx', 'nginx-selfsigned.key')
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False, ssl_context=(cert_path, key_path))
