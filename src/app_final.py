from flask import Flask, request, render_template, session, redirect, url_for
import pandas as pd
import joblib
import redis
import os
from datetime import datetime, timedelta
from urllib.parse import unquote


# دالة لجلب الـ IP الحقيقي سواء كنا محلياً أو على سيرفر رندر
def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        # السيرفر يعطي قائمة IPs، الأول هو الحقيقي
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

# --- 1. إعدادات النظام (Dynamic Paths) ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')

MODEL_PATH = os.path.join(DATA_DIR, 'waap_model.pkl')
LABEL_ENCODER_PATH = os.path.join(DATA_DIR, 'label_encoder.pkl')
LOG_FILE = os.path.join(DATA_DIR, 'waf_logs.txt')

app = Flask(__name__)
app.secret_key = 'malik_secret_key_123'

# التأكد من وجود مجلد الداتا
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# --- 2. تهيئة المحرك ---
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
try:
    r = redis.from_url(redis_url, decode_responses=True)
    try: 
        r.ping()
    except: 
        r = None
    
    # تحميل الموديل
    model = joblib.load(MODEL_PATH)
    le = joblib.load(LABEL_ENCODER_PATH)
    print("✅ [SYSTEM READY] Engine Active.")
except Exception as e:
    print(f"❌ [ERROR] {e}")
    r = None
    model = None
    le = None

# --- 3. التسجيل (توقيت الأردن UTC+3) ---
def log_event(ip, url, threat, action):
    jordan_time = datetime.utcnow() + timedelta(hours=3)
    timestamp = jordan_time.strftime("%Y-%m-%d %H:%M:%S")
    
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp},{ip},{url},{threat},{action}\n")

# --- 4. المنطق الأمني (Security Pipeline) ---
@app.before_request
def waap_pipeline():
    # استثناء الملفات الثابتة وروابط الخروج
    if request.path.startswith('/static') or request.path.startswith('/logout') or request.path.startswith('/favicon.ico'):
        return

    ip = get_client_ip()     
    decoded_path = unquote(request.full_path).lower() if request.full_path else ""


    # 1. فحص Rate Limit (Redis)
    # التعديل: إذا كان المستخدم "أدمن"، لا تفحص الـ Rate Limit

    is_admin = session.get('role') == 'admin'

    if r and not is_admin:  # <--- أضفنا (and not is_admin)
        try:
            req_count = r.incr(ip)
            if req_count == 1: r.expire(ip, 60)
            if req_count > 100:
                log_event(ip, request.path, "Rate Limit (DDoS)", "BLOCK")
                return render_template('blocked.html', reason="DDoS Attack Detected"), 429
        except: pass
    # تجهيز البيانات للفحص
    form_data = ""
    if request.method == 'POST':
        for key, value in request.form.items():
            form_data += f" {str(value).lower()}"
    full_payload = decoded_path + form_data

    # 2. فحص التواقيع (Signatures)
    signature_threat = None
    if "<script" in full_payload or "javascript:" in full_payload or "onerror" in full_payload:
        signature_threat = "XSS Attack Detected"
    elif "union" in full_payload or "select" in full_payload or " or 1=1" in full_payload or "'" in full_payload or "--" in full_payload or "#" in full_payload:
        signature_threat = "SQL Injection Detected"
    elif "/etc/passwd" in full_payload:
        signature_threat = "LFI Attack Detected"
        
    if signature_threat:
        log_event(ip, request.path, signature_threat, "BLOCK")
        return render_template('blocked.html', reason=signature_threat), 403

    # 3. فحص الذكاء الاصطناعي (AI Model)
    try:
        features = pd.DataFrame([{'flow_duration': 0.5, 'header_length': len(str(request.headers)), 'protocol_type': 6, 'duration': 0.2, 'rate': req_count if 'req_count' in locals() else 1}])
        
        if model and hasattr(model, "feature_names_in_"):
            features = features[model.feature_names_in_]
            pred_idx = model.predict(features)[0]
            ai_verdict = le.inverse_transform([pred_idx])[0]
            
            if ai_verdict != "BenignTraffic":
                safe_pages = ['/', '/login', '/user_home', '/dashboard', '/logs']
                if request.path in safe_pages:
                    log_event(ip, request.path, "AI Ignored (Safe Page)", "ALLOW")
                else:
                    log_event(ip, request.path, f"AI Detected: {ai_verdict}", "BLOCK")
                    return render_template('blocked.html', reason=f"Traffic Anomaly ({ai_verdict})"), 403
    except Exception as e:
        pass 

    # 4. حماية الصفحات الإدارية
    if request.path in ['/dashboard', '/logs']:
        if 'user' not in session or session.get('role') != 'admin':
            log_event(ip, request.path, "Unauthorized Admin Access", "BLOCK")
            return render_template('blocked.html', reason="Unauthorized Access (Admin Only)"), 403

    # 5. حماية صفحة المستخدم
    if request.path == '/user_home':
        if 'user' not in session:
            return redirect(url_for('login'))

    log_event(ip, request.path, "Clean Traffic", "ALLOW")

# --- 5. المسارات (Routes) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    # 1️⃣ أول خطوة: نجلب الـ IP الحقيقي ونخزنه
    real_ip = get_client_ip() 

    if request.method == 'POST':
        user = request.form.get('user')
        password = request.form.get('pass')

        # ... (أكواد التحقق من الباسوورد) ...

        if user == USERname and password == PASSword:
            session['user'] = user
            session['role'] = 'admin'
            
            # 2️⃣ عند تسجيل الدخول الناجح -> نستخدم real_ip
            log_event(real_ip, "/login", "Admin Login", "SUCCESS") # 👈 عدل هنا
            return redirect(url_for('dashboard'))
        
        else:
            # 3️⃣ عند فشل الدخول -> نستخدم real_ip
            log_event(real_ip, "/login", "Failed Login Attempt", "WARNING") # 👈 عدل هنا
            return render_template('login.html', error="Invalid Credentials")

    return render_template('login.html')
# --- مسار لوحة التحكم (Dashboard) ---
@app.route('/dashboard')
def dashboard():
    if session.get('role') != 'admin': 
        return redirect(url_for('login'))
    
    logs = []
    stats = {'ALLOW': 0, 'BLOCK': 0, 'XSS': 0, 'SQLi': 0, 'DDoS': 0, 'AI': 0}
    
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
            
            # 1. حساب الإحصائيات من كل السجلات
            for line in lines:
                parts = line.strip().split(',')
                if len(parts) >= 5:
                    threat = parts[3]
                    action = parts[4]
                    
                    if action == 'ALLOW': stats['ALLOW'] += 1
                    else: stats['BLOCK'] += 1
                    
                    if "XSS" in threat: stats['XSS'] += 1
                    elif "SQL" in threat: stats['SQLi'] += 1
                    elif "Rate" in threat or "DDoS" in threat: stats['DDoS'] += 1
                    elif "AI" in threat: stats['AI'] += 1
            
            # 2. تجهيز آخر 10 سجلات فقط للعرض المختصر
            for line in reversed(lines[-10:]):
                p = line.strip().split(',')
                if len(p) >= 5:
                    logs.append({
                        'time': p[0],
                        'ip': p[1],
                        'threat': p[3], # نرسل التهديد فقط
                        'action': p[4]
                    })
    
    # استدعاء صفحة الداشبورد الجديدة
    return render_template('dashboard.html', logs=logs, stats=stats)

# --- مسار السجلات الكاملة (Full Logs) ---
@app.route('/logs')
def show_logs():
    if session.get('role') != 'admin':
         return redirect(url_for('login'))

    logs_data = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()[::-1] # عكس الترتيب (الأحدث أولاً)
            for line in lines:
                parts = line.strip().split(',')
                if len(parts) >= 5:
                    logs_data.append({
                        'time': parts[0],
                        'ip': parts[1],
                        'data': f"URL: {parts[2]} | Threat: {parts[3]}", # دمج التفاصيل
                        'action': parts[4]
                    })

    # استدعاء صفحة السجلات التفصيلية
    return render_template('logs.html', logs=logs_data)

@app.route('/user_home')
def user_home():
    if 'user' not in session: 
        return redirect(url_for('login'))
    return render_template('home.html', user=session['user'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
