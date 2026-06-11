import os
import logging
import joblib  
import time
import re
import math
import sqlite3
import hashlib
import io  
import pandas as pd
import numpy as np
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file 
from collections import defaultdict, deque
from urllib.parse import unquote
from datetime import datetime, timedelta, timezone 
from pyngrok import ngrok 

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")

os.makedirs(LOG_DIR, exist_ok=True)
MODEL_PATH = os.path.join(DATA_DIR, 'waap_model.pkl')
LOG_FILE = os.path.join(LOG_DIR, "waap.log")

logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.getLogger('pyngrok').setLevel(logging.ERROR)

class JordanFormatter(logging.Formatter):
    def format(self, record):
        tz_jordan = timezone(timedelta(hours=3))
        dt = datetime.now(tz_jordan).strftime('%I:%M:%S %p')
        return f"[{dt}] | {record.msg}"

handler = logging.FileHandler(LOG_FILE)
handler.setFormatter(logging.Formatter("%(asctime)s|%(message)s"))
stream = logging.StreamHandler()
stream.setFormatter(JordanFormatter())

logging.basicConfig(level=logging.INFO, handlers=[handler, stream])

app = Flask(__name__)
app.secret_key = "WAAP_GATEWAY_PROJECT_2026_JUST"

try:
    model = joblib.load(MODEL_PATH)
    label_encoder = joblib.load(os.path.join(DATA_DIR, 'label_encoder.pkl'))
    model_columns = joblib.load(os.path.join(DATA_DIR, 'model_features.pkl'))
    logging.info(f"0.0.0.0 | SYSTEM_READY | AI_V8_ACTIVE")
except Exception as e:
    logging.error(f"0.0.0.0 | LOAD_ERROR | {e}")

def verify_user(username, password):
    hashed_input = hashlib.sha256(password.encode()).hexdigest()
    db_path = os.path.join(DATA_DIR, "users.db")
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT username, role FROM users WHERE username=? AND password=?", (username, hashed_input))
        user = cursor.fetchone()
        conn.close()
        return user 
    except Exception as e:
        logging.error(f"DATABASE_ERROR: {e}")
        return None

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
                    ip_part = parts[1].strip()
                    threat_type = parts[2].strip()
                    action = parts[3].strip()
                    timestamp = parts[0].strip()
                    if action == "BLOCK":
                        stats['BLOCK'] += 1
                        if "SQL" in threat_type: stats['SQLi'] += 1
                        elif "XSS" in threat_type: stats['XSS'] += 1
                        elif "DDOS" in threat_type: stats['DDoS'] += 1
                        else: stats['AI'] += 1
                    elif action == "ALLOW":
                        stats['ALLOW'] += 1
                    if threat_type not in ["SAFE_TRAFFIC", "SYSTEM_READY"]:
                        security_events.append({
                            'time': timestamp,
                            'ip': ip_part,
                            'threat': threat_type,
                            'action': action
                        })
    except Exception as e:
        print(f"Read Error: {e}")
    return stats, security_events[-15:][::-1]

def check_signatures(payload):
    sigs = [
        r"(\'|\"|%27|%22)\s+(or|and)\s+([\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+)", 
        r"union.*select", r"select.*from", r"insert.*into", r"drop\s+table", r"\'\s*--", r"\"\s*--",
        r"<script.*?>", r"alert\(", r"on\w+\s*=", r"<svg", r"<img", r"<iframe>", r"javascript:",
        r"\.\./", r"\.\.\\", r"etc/passwd", r"etc/shadow", r"/proc/self/"
    ]
    return any(re.search(sig, payload, re.I) for sig in sigs)

request_log = defaultdict(deque)
def is_rate_limited(ip):
    current_time = time.time()
    window = request_log[ip]
    while window and window[0] < current_time - 60: window.popleft()
    if len(window) >= 10: return True
    window.append(current_time)
    return False

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

@app.before_request
def security_check():
    if request.path in ['/health', '/blocked', '/logout', '/dashboard', '/logs', '/api/stats', '/add_user', '/export_report', '/api/latest_alert'] or request.path.startswith('/static/'):
        return

    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip() or request.remote_addr
    query = unquote(request.query_string.decode())
    body = unquote(request.get_data(as_text=True))
    full_payload = (query + " " + body).lower()

    if is_rate_limited(ip):
        logging.info(f"{ip} | DDOS_ATTACK | BLOCK")
        return redirect(url_for('blocked'))

    threat = "SAFE_TRAFFIC"
    is_malicious = False

    if check_signatures(full_payload):
        is_malicious = True
        if any(x in full_payload for x in ['etc/', 'passwd', '../']): threat = "LFI_ATTEMPT"
        elif any(x in full_payload for x in ['script', 'alert', 'onerror', 'onload', '<svg', '<img']): threat = "XSS_ATTACK"
        elif any(x in full_payload for x in ['union', 'select', 'or', '--']): threat = "SQL_INJECTION"
        else: threat = "MALICIOUS_REQUEST"

    if not is_malicious:
        try:
            f_df = extract_features_v8(request.path, query, body)
            probs = model.predict_proba(f_df)[0]
            ai_confidence = float(max(probs) * 100)
            if (probs[1] + probs[2]) >= 0.70:
                is_malicious = True
                threat = f"AI_ANOMALY ({ai_confidence:.1f}%)"
        except: pass

    if is_malicious:
        logging.info(f"{ip} | {threat} | BLOCK")
        return redirect(url_for('blocked'))
    
    if request.path in ['/', '/login'] and request.method == 'POST':
        return 

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
        user_data = verify_user(u, p)
        if user_data:
            username, role = user_data
            logging.info(f"{ip} | {username.upper()}_SUCCESS | ALLOW")
            session['user'], session['role'] = username, role
            return redirect(url_for('dashboard' if role == 'Administrator' else 'home'))
        logging.info(f"{ip} | FAILED_LOGIN | BLOCK")
        return render_template('login.html', error="Invalid Credentials")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if session.get('role') != 'Administrator': return redirect(url_for('login'))
    stats, logs_list = get_live_data()
    return render_template('dashboard.html', user=session['user'], stats=stats, logs=logs_list)

@app.route('/logs')
def logs():
    if session.get('role') != 'Administrator': return redirect(url_for('login'))
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

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if session.get('role') != 'Administrator': return redirect(url_for('login'))
    msg = None
    if request.method == 'POST':
        new_u, new_p, role = request.form.get('new_user'), request.form.get('new_pass'), request.form.get('role')
        hashed_p = hashlib.sha256(new_p.encode()).hexdigest()
        try:
            conn = sqlite3.connect(os.path.join(DATA_DIR, "users.db"))
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (new_u, hashed_p, role))
            conn.commit()
            conn.close()
            msg = f"✅ User '{new_u}' added!"
        except sqlite3.IntegrityError: msg = "❌ Error: Username exists!"
        except Exception as e: msg = f"❌ Error: {e}"
    return render_template('add_user.html', msg=msg)

@app.route('/export_report')
def export_report():
    if session.get('role') != 'Administrator': return redirect(url_for('login'))
    logs_data = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            for line in f:
                parts = line.strip().split('|')
                if len(parts) >= 4:
                    logs_data.append({"Timestamp": parts[0].strip(), "Source_IP": parts[1].strip(), "Threat": parts[2].strip(), "Action": parts[3].strip()})
    df = pd.DataFrame(logs_data)
    proxy = io.StringIO()
    df.to_csv(proxy, index=False)
    mem = io.BytesIO()
    mem.write(proxy.getvalue().encode('utf-8'))
    mem.seek(0)
    return send_file(mem, mimetype='text/csv', as_attachment=True, download_name=f"WAAP_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.csv")

@app.route('/api/latest_alert')
def latest_alert():
    if not os.path.exists(LOG_FILE): return jsonify(None)
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
            if not lines: return jsonify(None)
            last_line = lines[-1].strip().split('|')
            if len(last_line) >= 4 and last_line[3].strip() == "BLOCK":
                return jsonify({"time": last_line[0].strip(), "ip": last_line[1].strip(), "threat": last_line[2].strip()})
    except: pass
    return jsonify(None)

if __name__ == '__main__':
    TOKEN = "3Aja1DPgYYdYi3ECctzdtmQQwUh_6w18eRDP51rE9Xto23c9a"
    ngrok.set_auth_token(TOKEN)
    try:
        public_url = ngrok.connect(addr="https://localhost:5000", proto="http", bind_tls=True).public_url
        print(f"\nSYSTEM LIVE VIA NGINX: {public_url}\n")
    except Exception as e: print(f"Ngrok Warning: {e}")
    cert_path, key_path = os.path.join(PROJECT_ROOT, 'nginx', 'nginx-selfsigned.crt'), os.path.join(PROJECT_ROOT, 'nginx', 'nginx-selfsigned.key')
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False, ssl_context=(cert_path, key_path))
