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

print("🚀 Starting FINAL AI Training (Precision Mapping Mode)...")

# --- 2. تحميل البيانات (مع حماية الرام) ---
all_files = glob.glob(os.path.join(DATA_PATH, "*.csv"))
if not all_files:
    print("❌ No CSV files found!")
    exit()

# نأخذ أول 3 ملفات كعينة قوية
selected_files = all_files[:3]
print(f"📂 Loading data from {len(selected_files)} files...")

df_list = []
for file in selected_files:
    try:
        # نقرأ 150 ألف سطر فقط لحماية الرام
        df = pd.read_csv(file, nrows=150000)
        df_list.append(df)
    except Exception as e:
        print(f"⚠️ Skipped {os.path.basename(file)}")

full_df = pd.concat(df_list, ignore_index=True)

# --- 3. تنظيف وتوحيد الأعمدة (هنا يكمن السر!) ---
# قمت بنسخ الأسماء حرفياً من صورتك
# المفتاح (يسار): الاسم الذي يريده الكود
# القيمة (يمين): الاسم الموجود في ملفاتك
column_mapping = {
    'flow_duration': 'flow_duration',   # مطابق
    'header_length': 'Header_Length',   # كان يسبب المشكلة
    'protocol_type': 'Protocol Type',   # كان يسبب المشكلة (وجود مسافة)
    'duration': 'Duration',             # كان يسبب المشكلة (حرف كبير)
    'rate': 'Rate'                      # كان يسبب المشكلة (حرف كبير)
}

print("🔧 Mapping columns correctly...")
final_df = pd.DataFrame()

# نقل البيانات للأعمدة الصحيحة
for target_col, source_col in column_mapping.items():
    if source_col in full_df.columns:
        final_df[target_col] = full_df[source_col]
    else:
        print(f"❌ CRITICAL ERROR: Column {source_col} not found!")
        exit()

# إضافة عمود النتيجة (Label)
if 'label' in full_df.columns:
    final_df['label'] = full_df['label']
else:
    print("❌ Error: 'label' column not found!")
    exit()

# --- 4. حماية الرام (Sampling) ---
# إذا زادت البيانات عن 300 ألف، نأخذ عينة عشوائية
if len(final_df) > 300000:
    print("✂️ Optimizing dataset size for RAM safety...")
    final_df = final_df.sample(n=300000, random_state=42)

# تنظيف القيم
X = final_df.drop('label', axis=1)
y = final_df['label']
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

# --- 5. التدريب ---
print(f"📊 Training on {len(X)} clean records...")

le = LabelEncoder()
y_encoded = le.fit_transform(y.astype(str))

X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

print("🧠 Training Random Forest (This is the magic moment)...")
model = RandomForestClassifier(n_estimators=40, max_depth=20, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# --- 6. النتيجة ---
print("\n🔍 Evaluating...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print("="*40)
print(f"✅ FINAL MODEL ACCURACY: {accuracy * 100:.2f}%")
print("="*40)

print("\n💾 Saving High-Performance Model...")
joblib.dump(model, os.path.join(SAVE_PATH, 'waap_model.pkl'))
joblib.dump(le, os.path.join(SAVE_PATH, 'label_encoder.pkl'))
print("🎉 SYSTEM UPGRADED SUCCESSFULLY!")
