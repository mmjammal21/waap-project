import pandas as pd
import joblib
import re
import os
import logging
from flask import Flask, request, render_template, redirect, url_for, session

# --- الإعدادات ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "Malik_Secure_2026")

# --- تحميل الموديل V7 ---
try:
    model = joblib.load('data/waap_model.pkl')
    label_encoder = joblib.load('data/label_encoder.pkl')
    model_columns = joblib.load('data/model_features.pkl')
    logger.info("✅ System Ready: AI Engine V7 Balanced (91.30%)")
except Exception as e:
    logger.error(f"❌ Error loading AI: {e}")

# --- دالة استخراج الميزات (النسخة المستقرة) ---
def extract_features(path, data_string):
    features = {col: 0 for col in model_columns}
    text = (path + " " + data_string).lower()
    t_len = len(text) if len(text) > 0 else 1
    
    # حساب الأنماط (بدون الدومين)
    sql_k = len(re.findall(r"(union|select|insert|--|#|'|\"|or\s+1=1)", text))
    xss_k = len(re.findall(r"(<|>|script|alert|onerror|onload)", text))
    spec_chars = len(re.findall(r"[^a-zA-Z0-9\s]", text))
    
    features['url_length'] = len(path)
    features['sql_keywords'] = sql_k
    features['xss_keywords'] = xss_k
    features['special_chars'] = spec_chars
    features['char_complexity'] = spec_chars / t_len
    features['code_density'] = (sql_k * 2 + xss_k * 2) / t_len 
    return pd.DataFrame([features])

# --- حارس الأمان (بدون حظر خاطئ) ---
@app.before_request
def security_check():
    # استثناء الصفحات الأساسية من فحص الـ AI لضمان الدخول
    if request.path in ['/blocked', '/logout', '/static/'] or request.path.endswith(('.css', '.js')):
        return

    # جمع البيانات للفحص
    query = request.query_string.decode()
    # نأخذ قيم الفورم فقط إذا وجدت
    form_data = " ".join(request.form.values()) if request.form else ""
    
    # إذا كان مجرد دخول عادي للصفحة بدون بيانات، اسمح له بالمرور
    if not query and not form_data:
        return

    # تحليل AI
    f_df = extract_features(request.path, query + " " + form_data)
    prediction = model.predict(f_df)[0]
    label = label_encoder.inverse_transform([prediction])[0]

    if label != 'Benign':
        logger.warning(f"🚨 AI Blocked Attack: {label}")
        return redirect(url_for('blocked'))

# --- المسارات ---
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # تأكد أن هذه الأسماء (identity) و (access_key) مطابقة لملف HTML لديك
        user_input = request.form.get('identity')
        pass_input = request.form.get('access_key')
        
        logger.info(f"Login attempt: {user_input}") # سجل لمراقبة الدخول في Render

        if user_input == 'admin' and pass_input == '123':
            session['user'] = 'admin'
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error="Invalid Credentials")
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session['user'])

@app.route('/blocked')
def blocked():
    return render_template('blocked.html'), 403

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
