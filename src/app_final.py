import os
import re
import joblib
import pandas as pd
import redis
from flask import Flask, request, render_template, redirect, url_for, session
from datetime import datetime

# --- إعدادات التطبيق ---
app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session'  # مفتاح تشفير الجلسة

# --- إعدادات Redis (تلقائي أو محلي) ---
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
r = redis.from_url(redis_url)

# --- مسارات الملفات والموديل ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, '../data')
LOG_FILE = os.path.join(BASE_DIR, 'templates/logs.txt') # ملف السجلات

# تحميل الموديل والذكاء الاصطناعي
MODEL_PATH = os.path.join(DATA_DIR, 'waap_model.pkl')
LE_PATH = os.path.join(DATA_DIR, 'label_encoder.pkl')
COLS_PATH = os.path.join(DATA_DIR, 'model_features.pkl')

rf_model = None
label_encoder = None
model_columns = None

print("⏳ Loading AI Model...")
try:
    rf_model = joblib.load(MODEL_PATH)
    label_encoder = joblib.load(LE_PATH)
    model_columns = joblib.load(COLS_PATH)
    print("✅ AI Model Loaded Successfully!")
except Exception as e:
    print(f"⚠️ Warning: Could not load AI model. Running in Fallback Mode. Error: {e}")

# --- دالة 1: جلب IP الزائر الحقيقي (تجاوز البروكسي) ---
def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

# --- دالة 2: تسجيل السجلات (Log Event) ---
def log_event(ip, url, threat_type, action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp},{ip},{url},{threat_type},{action}\n"
    
    # كتابة السجل في ملف
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Error writing log: {e}")

# --- دالة 3: استخراج الميزات للموديل (Feature Extraction) ---
def extract_features(url, body):
    features = {col: 0 for col in model_columns} if model_columns else {}
    if not model_columns: return pd.DataFrame([features])

    text = url + " " + body
    
    # ميزات بسيطة يحتاجها الموديل
    features['url_length'] = len(url)
    features['sql_keywords'] = len(re.findall(r"(union|select|insert|drop|alter|--)", text, re.IGNORECASE))
    features['xss_keywords'] = len(re.findall(r"(<script>|alert|onerror|onload)", text, re.IGNORECASE))
    features['special_chars'] = len(re.findall(r"['\";<>]", text))
    
    # تعبئة باقي الميزات بأصفار للحفاظ على شكل الداتا
    return pd.DataFrame([features])

# ==========================================
# 🛡️ نظام الحماية الرئيسي (WAAP Pipeline) 🛡️
# ==========================================
@app.before_request
def waap_pipeline():
    # استثناء الملفات الثابتة والصور من الفحص لتسريع الموقع
    if request.path.startswith('/static') or request.path == '/favicon.ico':
        return

    # 1. جلب الـ IP الحقيقي
    ip = get_client_ip()
    
    # 2. استثناء الأدمن من فحص Rate Limit (White-listing)
    is_admin = session.get('role') == 'admin'

    # 3. فحص DDoS / Rate Limiting (باستثناء الأدمن)
    if not is_admin:
        try:
            req_count = r.incr(ip)
            if req_count == 1:
                r.expire(ip, 60) # إعادة تعيين العداد كل دقيقة
            
            if req_count > 100: # السماح بـ 100 طلب في الدقيقة
                log_event(ip, request.path, "DDoS (Rate Limit)", "BLOCK")
                return render_template('blocked.html', reason="Too Many Requests (DDoS Protection)"), 429
        except:
            pass # في حال فشل Redis لا نوقف الموقع

    # 4. تجهيز البيانات للفحص
    url = request.path
    # التعامل مع البيانات بأمان لتجنب الأخطاء
    try:
        body = request.get_data(as_text=True) or ""
    except:
        body = ""
        
    full_text = (url + body).lower()

    # 5. الفحص السريع (Signatures) - SQLi & XSS
    sql_pattern = r"(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\bdrop\b.*\btable\b|' OR 1=1|admin' --)"
    xss_pattern = r"(<script>|javascript:|onerror=|onload=|alert\()"

    if re.search(sql_pattern, full_text, re.IGNORECASE):
        log_event(ip, url, "SQL Injection (Signature)", "BLOCK")
        return render_template('blocked.html', reason="SQL Injection Detected"), 403

    if re.search(xss_pattern, full_text, re.IGNORECASE):
        log_event(ip, url, "XSS Attack (Signature)", "BLOCK")
        return render_template('blocked.html', reason="XSS Attack Detected"), 403

    # 6. الفحص الذكي (AI Model Check)
    if rf_model and model_columns:
        try:
            input_data = extract_features(url, body)
            # التأكد من ترتيب الأعمدة كما تدرب عليها الموديل
            input_data = input_data.reindex(columns=model_columns, fill_value=0)
            
            prediction = rf_model.predict(input_data)[0]
            confidence = rf_model.predict_proba(input_data).max()

            # إذا كان الموديل متأكداً أنه هجوم بنسبة عالية
            if prediction == 1 and confidence > 0.85: 
                log_event(ip, url, f"AI Detected Attack ({confidence:.2f})", "BLOCK")
                return render_template('blocked.html', reason="AI Model Detected Malicious Activity"), 403
        except Exception as e:
            print(f"AI Check Error: {e}")

    # إذا مر من كل الفحوصات -> زيارة نظيفة
    # (اختياري: لا نسجل كل زيارة نظيفة لتوفير المساحة، أو نسجلها للمراقبة)
    # log_event(ip, url, "Clean Traffic", "ALLOW") 

# ==========================================
# 🌐 صفحات الموقع (Routes) 🌐
# ==========================================

@app.route('/')
def index():
    return redirect(url_for('login'))

# --- صفحة تسجيل الدخول (المعدلة والمصلحة) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    real_ip = get_client_ip() # استخدام الـ IP الحقيقي

    if request.method == 'POST':
        user = request.form.get('user')
        password = request.form.get('pass')

        # استخدام بيانات ثابتة لتجنب الأخطاء (Hardcoded)
        if user == 'admin' and password == '123':
            session['user'] = user
            session['role'] = 'admin'
            log_event(real_ip, "/login", "Admin Login Success", "ALLOW")
            return redirect(url_for('dashboard'))


          # --- 2. حالة المستخدم العادي (يدخل على صفحة المستخدم) --- # 👈 هذا الإضافة الجديدة
        elif user == 'user' and password == '123':
            session['user'] = user
            session['role'] = 'user'
            log_event(real_ip, "/login", "User Login Success", "ALLOW")
            return redirect(url_for('user_home'))


        else:
            log_event(real_ip, "/login", "Failed Login Attempt", "WARNING")
            return render_template('login.html', error="Invalid Credentials")

    return render_template('login.html')

# --- لوحة التحكم (Dashboard) ---
@app.route('/dashboard')
def dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    # قراءة السجلات لعرضها
    logs = []
    stats = {'SQLi': 0, 'XSS': 0, 'DDoS': 0, 'AI': 0, 'BLOCK': 0, 'ALLOW': 0}
    
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            # قراءة آخر 50 سطر فقط للأداء
            lines = f.readlines()[-50:] 
            for line in reversed(lines): # الأحدث أولاً
                p = line.strip().split(',')
                if len(p) >= 5:
                    logs.append({
                        'time': p[0],
                        'ip': p[1],
                        'threat': p[3],
                        'action': p[4]
                    })
                    
                    # تجميع الإحصائيات
                    if 'SQL' in p[3]: stats['SQLi'] += 1
                    elif 'XSS' in p[3]: stats['XSS'] += 1
                    elif 'DDoS' in p[3]: stats['DDoS'] += 1
                    elif 'AI' in p[3]: stats['AI'] += 1
                    
                    if 'BLOCK' in p[4]: stats['BLOCK'] += 1
                    else: stats['ALLOW'] += 1

    return render_template('dashboard.html', logs=logs, stats=stats)

# --- صفحة المستخدم (User Home) ---
@app.route('/user_home')
def user_home():
    if 'user' not in session: 
        return redirect(url_for('login'))
    return render_template('home.html', user=session['user'])

# --- تسجيل الخروج ---
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- عرض السجلات الكاملة ---
@app.route('/logs')
def show_logs():
    if session.get('role') != 'admin':
         return redirect(url_for('login'))

    logs_data = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()[::-1]
            for line in lines:
                parts = line.strip().split(',')
                if len(parts) >= 5:
                    logs_data.append({
                        'time': parts[0],
                        'ip': parts[1],
                        'data': f"URL: {parts[2]} | Threat: {parts[3]}",
                        'action': parts[4]
                    })

    return render_template('logs.html', logs=logs_data)

# تشغيل التطبيق
if __name__ == '__main__':
    # وضع debug=True يساعدك في رؤية الأخطاء في المتصفح
    app.run(host='0.0.0.0', port=5000, debug=True)
