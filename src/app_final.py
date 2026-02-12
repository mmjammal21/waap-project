import pandas as pd
import joblib
import re
import os
import logging
from flask import Flask, request, render_template, redirect, url_for, session

# --- الإعدادات وسجلات النظام ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "Malik_Secure_2026")

# --- تحميل محرك الذكاء الاصطناعي (V7) ---
MODEL_PATH = 'data/waap_model.pkl'
ENCODER_PATH = 'data/label_encoder.pkl'

try:
    model = joblib.load(MODEL_PATH)
    label_encoder = joblib.load(ENCODER_PATH)
    model_columns = joblib.load('data/model_features.pkl')
    logger.info("2026-02-12 | INFO | ✅ AI Engine Standardized for Render Deployment (V7)")
except Exception as e:
    logger.error(f"❌ Error loading AI components: {e}")

# --- 🧠 خوارزمية استخراج الميزات المحدثة ---
def extract_features(path, query, body):
    features = {col: 0 for col in model_columns}
    
    # تنظيف المحتوى: نركز فقط على ما أرسله المستخدم فعلياً
    payload = (path + " " + query + " " + body).lower().strip()
    # إذا كان الطلب فارغاً تماماً (مثل دخول الصفحة لأول مرة)، نضع طولاً افتراضياً لتجنب القسمة على صفر
    payload_len = len(payload) if len(payload) > 0 else 1
    
    # حساب الميزات الأساسية
    sql_k = len(re.findall(r"(union|select|insert|drop|--|#|'|\"|or\s+1=1|admin'|concat)", payload))
    xss_k = len(re.findall(r"(<|>|script|alert|onerror|onload|iframe|javascript:)", payload))
    spec_chars = len(re.findall(r"[^a-zA-Z0-9\s]", payload))
    
    features['url_length'] = len(path)
    features['sql_keywords'] = sql_k
    features['xss_keywords'] = xss_k
    features['special_chars'] = spec_chars
    
    # معادلة التعقيد الرياضي:
    # $$ \text{char\_complexity} = \frac{\text{special\_chars}}{\text{payload\_len}} $$
    features['char_complexity'] = spec_chars / payload_len
    features['code_density'] = (sql_k * 2 + xss_k * 2) / payload_len 
    
    return pd.DataFrame([features])

# --- 🛡️ حارس البوابة (Security Middleware) ---
@app.before_request
def security_check():
    # 1. استثناء الملفات الثابتة والروابط الإدارية
    static_extensions = ('.css', '.js', '.png', '.jpg', '.ico', '.svg')
    if request.path.endswith(static_extensions) or request.path in ['/blocked', '/logout']:
        return

    # 2. القاعدة الذهبية: إذا كان المستخدم يطلب الصفحة الرئيسية أو الدخول بدون أي "باراميترز" أو "بيانات"
    # نسمح له بالمرور فوراً دون إزعاج الموديل، لأن الطلب الفارغ مستحيل أن يكون هجوماً.
    query = request.query_string.decode()
    body = request.get_data(as_text=True)
    
    if not query and not body and request.path in ['/', '/login']:
        return # مرور آمن للمستخدم الطبيعي

    # 3. تحليل الطلبات التي تحتوي على بيانات فقط
    features_df = extract_features(request.path, query, body)
    
    # فحص "عتبة الخطورة": إذا كانت الرموز الخاصة قليلة جداً ولا توجد كلمات مفتاحية، فهو طلب سليم.
    if features_df['special_chars'].iloc[0] < 3 and features_df['sql_keywords'].iloc[0] == 0:
        return

    prediction = model.predict(features_df)[0]
    label = label_encoder.inverse_transform([prediction])[0]

    if label != 'Benign':
        logger.warning(f"🚨 AI BLOCKED: {label} | Path: {request.path}")
        return redirect(url_for('blocked'))

# --- 🌐 المسارات (Routes) ---

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identity = request.form.get('identity')
        access_key = request.form.get('access_key')
        
        if identity in ['admin', 'user'] and access_key == '123':
            session['user'] = identity
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
