import pandas as pd
import numpy as np
import joblib
import os
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
from sklearn.utils import resample 

# المسارات المطلقة
CSIC_FILE = '/home/malik/graduation_project/data/csic_2010/csic_database.csv'
IOT_DIR   = '/home/malik/graduation_project/data/waap_dataset_2026/'
FUZZ_FILE = '/home/malik/graduation_project/data/fuzzing_data/payload_full.csv'
SAVE_PATH = '/home/malik/graduation_project/data/'

def extract_features(text):
    text = str(text).lower()
    url_len = len(text) if len(text) > 0 else 1
    spec_chars = len(re.findall(r"[^a-zA-Z0-9\s]", text))
    sql_k = len(re.findall(r"(union|select|insert|drop|--|#|/\*|'|\"|%27|%23)", text))
    xss_k = len(re.findall(r"(<|>|script|alert|onerror|onload|iframe|javascript:|%3c|%3e)", text))
    
    return {
        'url_length': url_len,
        'sql_keywords': sql_k,
        'xss_keywords': xss_k,
        'special_chars': spec_chars,
        'char_complexity': spec_chars / url_len,
        'code_density': (sql_k + xss_k) / url_len
    }

def group_labels(label):
    label = str(label).lower()
    if label in ['benign', 'normal', 'benigntraffic', 'norm', '0', '28', '3']: return 'Benign'
    if any(x in label for x in ['sqli', 'xss', 'anom', 'fuzzing', 'payload', 'attack', 'scan', 'command', 'upload', 'vuln']): return 'Web_Attack'
    return 'Network_Attack'

print("🚀 Starting ULTIMATE Hybrid Training V7 (Balanced Edition)...")

# --- تحميل البيانات ---
df_fuzz = pd.read_csv(FUZZ_FILE, nrows=70000)
f_X = df_fuzz['payload'].apply(lambda x: pd.Series(extract_features(x)))
f_y = df_fuzz['label']

df_web = pd.read_csv(CSIC_FILE, nrows=70000)
w_X = df_web['URL'].apply(lambda x: pd.Series(extract_features(x)))
w_y = df_web['classification']

iot_files = [f for f in os.listdir(IOT_DIR) if f.endswith('.csv')]
df_iot = pd.read_csv(os.path.join(IOT_DIR, iot_files[0]), nrows=70000)
iot_X = pd.DataFrame()
iot_X['url_length'] = (df_iot['Header_Length'] / 5).fillna(0).astype(int)
iot_X['sql_keywords'] = 0
iot_X['xss_keywords'] = 0
iot_X['special_chars'] = (df_iot['Rate'] % 50).fillna(0).astype(int)
iot_X['char_complexity'] = iot_X['special_chars'] / iot_X['url_length'].replace(0, 1)
iot_X['code_density'] = 0
iot_y = df_iot['label']

# --- الدمج والموازنة ---
X_full = pd.concat([f_X, w_X, iot_X], ignore_index=True)
y_full = pd.concat([f_y, w_y, iot_y], ignore_index=True).apply(group_labels)

combined = pd.concat([X_full, y_full.rename('label')], axis=1)
benign = combined[combined['label'] == 'Benign']
web = combined[combined['label'] == 'Web_Attack']
net = combined[combined['label'] == 'Network_Attack']

benign_res = resample(benign, replace=True, n_samples=40000, random_state=42)
web_res = resample(web, replace=True, n_samples=40000, random_state=42)
net_res = resample(net, replace=True, n_samples=40000, random_state=42)

final_df = pd.concat([benign_res, web_res, net_res])
X = final_df.drop('label', axis=1)
y = final_df['label']

le = LabelEncoder()
y_encoded = le.fit_transform(y)
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.15, random_state=42, stratify=y_encoded)

# --- التدريب المكثف (تم تعديل المعاملات لتقليل الحجم) ---
print(f"🧠 Training Balanced Random Forest on {len(X)} samples...")
# التعديل هنا: تقليل n_estimators و max_depth لتقليل استهلاك الـ RAM في Render
model = RandomForestClassifier(n_estimators=100, max_depth=20, class_weight='balanced', n_jobs=-1, random_state=42)
model.fit(X_train, y_train)

# --- النتائج ---
y_pred = model.predict(X_test)
print("\n📊 --- BALANCED REPORT (V7) ---")
print(classification_report(y_test, y_pred, target_names=le.classes_))

# التعديل هنا: استخدام compress=3 لتقليل حجم الملف النهائي
joblib.dump(model, os.path.join(SAVE_PATH, 'waap_model.pkl'), compress=3)
joblib.dump(le, os.path.join(SAVE_PATH, 'label_encoder.pkl'))
joblib.dump(X.columns.tolist(), os.path.join(SAVE_PATH, 'model_features.pkl'))

print(f"✅ V7 Saved! New Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
print("🎯 FINAL Mapping:", dict(zip(le.classes_, le.transform(le.classes_))))
