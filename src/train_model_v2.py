import pandas as pd
import numpy as np
import glob
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report

# --- 1. إعدادات المسار ---
DATA_PATH = '/home/malik/graduation_project/data/waap_dataset_2026/'
SAVE_PATH = '/home/malik/graduation_project/data'

print("🚀 Starting Optimized AI Training (RAM Safe Mode)...")

# --- 2. تحميل البيانات (Smart Sampling) ---
all_files = glob.glob(os.path.join(DATA_PATH, "*.csv"))

if not all_files:
    print(f"❌ Error: No CSV files found in {DATA_PATH}")
    exit()

# نأخذ أول 3 ملفات فقط لتخفيف الحمل
selected_files = all_files[:3]
print(f"📂 Reading data from {len(selected_files)} files...")

df_list = []
for file in selected_files:
    try:
        # نقرأ فقط 150,000 سطر من كل ملف لضمان عدم امتلاء الرام
        df = pd.read_csv(file, nrows=150000) 
        df_list.append(df)
    except Exception as e:
        print(f"⚠️ Skipped {os.path.basename(file)}: {e}")

if not df_list:
    print("❌ Failed to load data.")
    exit()

full_df = pd.concat(df_list, ignore_index=True)

# --- 3. تنظيف البيانات ---
full_df.columns = full_df.columns.str.strip().str.lower()

# الأعمدة المطلوبة
required_features = ['flow_duration', 'header_length', 'protocol_type', 'duration', 'rate']
existing_cols = full_df.columns.tolist()

feature_map = {
    'flow_duration': ['flow duration', 'flow_duration'],
    'header_length': ['header length', 'header_length', 'tot len'],
    'protocol_type': ['protocol', 'protocol type'],
    'duration': ['duration'],
    'rate': ['rate', 'srate']
}

final_features = []
for req in required_features:
    found = False
    for candidate in feature_map.get(req, []):
        if candidate in existing_cols:
            final_features.append(candidate)
            found = True
            break
    if not found:
        full_df[req] = 0
        final_features.append(req)

# تحديد الهدف (Label)
label_col = 'label' if 'label' in full_df.columns else 'class'
if not label_col:
    print("❌ Error: Label column not found.")
    exit()

# --- خطوة مهمة جداً: تقليل حجم البيانات عشوائياً إذا كانت ضخمة ---
# إذا كان العدد الكلي أكبر من 300 ألف، نأخذ عينة عشوائية بحجم 300 ألف فقط
# هذا يضمن أن الرام لن تمتلئ
MAX_RECORDS = 300000
if len(full_df) > MAX_RECORDS:
    print(f"⚠️ Data is too large ({len(full_df)} records). Sampling {MAX_RECORDS} random records to save RAM...")
    full_df = full_df.sample(n=MAX_RECORDS, random_state=42)

X = full_df[final_features]
y = full_df[label_col]

# تنظيف الأرقام
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

# --- 4. التدريب ---
print(f"📊 Training on {len(X)} records...")

le = LabelEncoder()
y_encoded = le.fit_transform(y.astype(str))

X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

print("🧠 Training Random Forest (Optimized)...")
# قللنا عدد الأشجار (n_estimators) وحددنا العمق (max_depth) لتقليل استهلاك الذاكرة
model = RandomForestClassifier(n_estimators=30, max_depth=15, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# --- 5. التقييم والحفظ ---
print("\n🔍 Evaluating...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print("="*40)
print(f"✅ MODEL ACCURACY: {accuracy * 100:.2f}%")
print("="*40)

print("\n💾 Saving Model...")
joblib.dump(model, os.path.join(SAVE_PATH, 'waap_model.pkl'))
joblib.dump(le, os.path.join(SAVE_PATH, 'label_encoder.pkl'))
print("🎉 Done! Model is ready and saved.")
