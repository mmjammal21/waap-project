import os
import re
import joblib
import pandas as pd
import redis
from flask import Flask, request, render_template, redirect, url_for, session
from urllib.parse import unquote
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session'

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
r = redis.from_url(redis_url)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, '../data')
LOG_FILE = os.path.join(BASE_DIR, 'templates/logs.txt')

MODEL_PATH = os.path.join(DATA_DIR, 'waap_model.pkl')
LE_PATH = os.path.join(DATA_DIR, 'label_encoder.pkl')
COLS_PATH = os.path.join(DATA_DIR, 'model_features.pkl')

rf_model = None
model_columns = None

try:
    rf_model = joblib.load(MODEL_PATH)
    model_columns = joblib.load(COLS_PATH)
    print("✅ AI Model Loaded Successfully!")
except Exception as e:
    print(f"⚠️ Warning: Model load failed: {e}")

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def log_event(ip, url, threat_type, action):
    jordan_time = datetime.utcnow() + timedelta(hours=3)
    timestamp = jordan_time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp}|{ip}|{url}|{threat_type}|{action}\n"
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry)
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(f"Error logs: {e}")

def extract_features(url, body):
    features = {col: 0 for col in model_columns} if model_columns else {}
    if not model_columns: return pd.DataFrame([features])
    text = url + " " + body
    features['url_length'] = len(url)
    features['sql_keywords'] = len(re.findall(r"(union|select|insert|drop|alter|--)", text, re.IGNORECASE))
    features['xss_keywords'] = len(re.findall(r"(<script>|alert|onerror|onload)", text, re.IGNORECASE))
    
    # 🔥 التعديل الجوهري: حساب كل الرموز الغريبة
    features['special_chars'] = len(re.findall(r"[^a-zA-Z0-9\s]", text))
    
    return pd.DataFrame([features])

@app.before_request
def waap_pipeline():
    if request.path.startswith('/static') or request.path == '/favicon.ico': return
    ip = get_client_ip()
    
    # Rate Limiting
    if session.get('role') != 'admin':
        try:
            req_count = r.incr(ip)
            if req_count == 1: r.expire(ip, 60)
            if req_count > 100:
                log_event(ip, request.path, "DDoS (Rate Limit)", "BLOCK")
                return render_template('blocked.html', reason="Too Many Requests"), 429
        except: pass

    raw_path = request.full_path if request.query_string else request.path
    url = unquote(raw_path)
    try: body = request.get_data(as_text=True) or ""
    except: body = ""
    full_text = (url + " " + body).lower()

    # Signatures
    if re.search(r"(\.\./|\.\.\\|/etc/passwd|/bin/sh|cmd=)", full_text, re.IGNORECASE):
        log_event(ip, url, "Path Traversal / LFI Attempt", "BLOCK")
        return render_template('blocked.html', reason="Illegal System Access"), 403

    if re.search(r"(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\bdrop\b.*\btable\b|'?\s*OR\s+1=1|admin'\s*--)", full_text, re.IGNORECASE):
        log_event(ip, url, "SQL Injection (Signature)", "BLOCK")
        return render_template('blocked.html', reason="SQL Injection Detected"), 403

    if re.search(r"(<script>|javascript:|onerror=|onload=|alert\()", full_text, re.IGNORECASE):
        log_event(ip, url, "XSS Attack (Signature)", "BLOCK")
        return render_template('blocked.html', reason="XSS Attack Detected"), 403

    # 🔥 AI Check (مع التعديلات القوية)
    if rf_model and model_columns:
        try:
            input_data = extract_features(url, body).reindex(columns=model_columns, fill_value=0)
            prediction = rf_model.predict(input_data)[0]
            confidence = rf_model.predict_proba(input_data).max()

            # 🛠️ مفتاح المحاكاة (Simulation Key)
            if "ai-test" in url:
                prediction = 1
                confidence = 0.99

            if prediction == 1 and confidence > 0.35:
                log_event(ip, url, f"AI Detected Attack ({confidence:.2f})", "BLOCK")
                return render_template('blocked.html', reason="AI Model Detected Malicious Activity"), 403
        except Exception as e:
            print(f"AI Check Error: {e}")

@app.route('/')
def index(): return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('user', '').strip()
        pwd = request.form.get('pass', '').strip()
        ip = get_client_ip()
        
        if user == 'admin' and pwd == '123':
            session['user'], session['role'] = user, 'admin'
            log_event(ip, "/login", "Admin Login Success", "ALLOW")
            return redirect(url_for('dashboard'))
        elif user == 'user' and pwd == '123':
            session['user'], session['role'] = user, 'user'
            log_event(ip, "/login", "User Login Success", "ALLOW")
            return redirect(url_for('user_home'))
        else:
            log_event(ip, "/login", "Failed Login Attempt", "WARNING")
            return render_template('login.html', error="Invalid Credentials")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if session.get('role') != 'admin': return redirect(url_for('login'))
    logs, stats = [], {'SQLi': 0, 'XSS': 0, 'DDoS': 0, 'AI': 0, 'BLOCK': 0, 'ALLOW': 0}
    
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            all_lines = f.readlines()
            for line in all_lines:
                p = line.strip().split('|')
                if len(p) >= 5:
                    t = p[3]
                    if 'SQL' in t: stats['SQLi'] += 1
                    elif 'XSS' in t: stats['XSS'] += 1
                    elif 'DDoS' in t: stats['DDoS'] += 1
                    elif 'AI' in t: stats['AI'] += 1
                    if 'BLOCK' in p[4]: stats['BLOCK'] += 1
                    else: stats['ALLOW'] += 1
            
            for line in reversed(all_lines[-15:]):
                p = line.strip().split('|')
                if len(p) >= 5: logs.append({'time': p[0], 'ip': p[1], 'threat': p[3], 'action': p[4]})

    return render_template('dashboard.html', logs=logs, stats=stats)

@app.route('/user_home')
def user_home():
    if 'user' not in session: return redirect(url_for('login'))
    ip = get_client_ip()
    ua = request.headers.get('User-Agent') or "Unknown"
    return render_template('home.html', user=session['user'], ip=ip, ua=ua, os="Windows", browser="Chrome")

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

@app.route('/logs')
def show_logs():
    if session.get('role') != 'admin': return redirect(url_for('login'))
    logs_data = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            for line in reversed(f.readlines()):
                p = line.strip().split('|')
                if len(p) >= 5: logs_data.append({'time': p[0], 'ip': p[1], 'url': p[2], 'threat': p[3], 'action': p[4]})
    return render_template('logs.html', logs=logs_data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
