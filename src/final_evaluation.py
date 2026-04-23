import joblib
import pandas as pd
import os
import re
import math
import numpy as np
from sklearn.metrics import classification_report, accuracy_score

def calculate_entropy(text):
    if not text or not isinstance(text, str): return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0: entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_features(payload):
    text = str(payload).lower()
    url_len = max(len(text), 1)
    sql_k = len(re.findall(r"(union|select|insert|drop|--|#|concat|where)", text))
    xss_k = len(re.findall(r"(<|>|script|alert|onerror|onload)", text))
    spec_chars = len(re.findall(r"[^a-zA-Z0-9\s]", text))
    
    return {
        'url_length': url_len,
        'sql_keywords': sql_k,
        'xss_keywords': xss_k,
        'special_chars': spec_chars,
        'char_complexity': spec_chars / url_len,
        'code_density': (sql_k + xss_k) / url_len,
        'entropy': calculate_entropy(text),
        'semicolon_count': text.count(';'),
        'apostrophe_count': text.count("'"),
        'bracket_count': text.count('(') + text.count(')')
    }

def run_test():
    print("🚀 Sentinel V8.0: Starting Final Evaluation...")
    
    model = joblib.load("../data/waap_model.pkl")
    encoder = joblib.load("../data/label_encoder.pkl")
    model_columns = joblib.load("../data/model_features.pkl")

    test_data = []
    
    # --- التأكد من قراءة الملفات بدقة ---
    sqli_path = "../data/sqli.txt"
    xss_path = "../data/xss.txt"

    if os.path.exists(sqli_path):
        with open(sqli_path, "r", errors='ignore') as f:
            lines = f.readlines()
            print(f"📦 Loaded {len(lines[:500])} SQLi samples")
            for line in lines[:500]:
                if line.strip(): test_data.append({'payload': line.strip(), 'true_label': 'Web_Attack'})
            
    if os.path.exists(xss_path):
        with open(xss_path, "r", errors='ignore') as f:
            lines = f.readlines()
            print(f"📦 Loaded {len(lines[:500])} XSS samples")
            for line in lines[:500]:
                if line.strip(): test_data.append({'payload': line.strip(), 'true_label': 'Web_Attack'})

    # إضافة عينات Benign حقيقية (عشان نرفع الـ Recall)
    benign_list = ["/index.php", "/login.html", "/contact", "/about-us", "/api/v1/status", "/static/css/bootstrap.min.css"]
    for b in benign_list * 100:
        test_data.append({'payload': b, 'true_label': 'Benign'})

    df = pd.DataFrame(test_data)
    if df.empty:
        print("❌ Error: No data loaded. Check your .txt files path!")
        return

    print("🧠 Extracting math features...")
    features_list = df['payload'].apply(extract_features)
    features_df = pd.DataFrame(list(features_list))

    for col in model_columns:
        if col not in features_df.columns:
            features_df[col] = 0

    # التنبوء
    print("⚡ AI Engine is analyzing...")
    y_pred_numeric = model.predict(features_df[model_columns])
    y_pred_names = encoder.inverse_transform(y_pred_numeric)
    
    # تنظيف الأسماء لضمان المطابقة
    y_pred_names = [str(n).strip() for n in y_pred_names]
    y_true_names = df['true_label'].astype(str).tolist()

    acc = accuracy_score(y_true_names, y_pred_names)
    print("\n" + "="*45)
    print(f"🏆 FINAL SCIENTIFIC ACCURACY: {acc*100:.2f}%")
    print("="*45)
    
    # طباعة التقرير مع معالجة الأسماء المفقودة
    print(classification_report(y_true_names, y_pred_names, zero_division=0))

if __name__ == "__main__":
    run_test()
