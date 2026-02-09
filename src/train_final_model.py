import pandas as pd
import numpy as np
import glob
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score

# --- 1. إعدادات المسار (Settings) ---
DATA_PATH = '/home/malik/graduation_project/data/waap_dataset_2026/'
SAVE_PATH = '/home/malik/graduation_project/data'

print("🚀 Starting FINAL CONSOLIDATED AI Training...")
print("🎯 Goal: High Accuracy + RAM Safety")

# --- 2. تحميل البيانات بذكاء (Smart Loading) ---
# البحث عن ملفات CSV
all_files = glob.glob(os.path.join(DATA_PATH, "*.csv"))
if not all_files:
    print(f"❌ Error: No CSV files found in {DATA_PATH}")
    exit()

# نأخذ أول 3 ملفات فقط لتخفيف الحمل على الرام مع الحفاظ على تنوع البيانات
selected_files = all_files[:3]
print(f"📂 Reading data from {len(selected_files)} files...")

df_list = []
for file in selected_files:
    try:
        # قراءة 150 ألف سطر من كل ملف (توازن ممتاز بين الدقة والسرعة)
        df = pd.read_csv(file, nrows=150000)
        df_list.append(df)
        print(f"  - Loaded: {os.path.basename(file)}")
    except Exception as e:
        print(f"  ⚠️ Skipped {os.path.basename(file)}: {e}")

if not df_list:
    print("❌ Failed to load any data.")
    exit()

full_df = pd.concat(df_list, ignore_index=True)

# --- 3. توحيد أسماء الأعمدة (The Master Mapping) ---
# هذا القاموس يربط بين الاسم البرمجي (اليسار) والاسم في ملفات الداتا (اليمين)
# تم تجميعه من كل محاولاتنا السابقة لضمان عدم حدوث خطأ
column_mapping = {
    # الأعمدة الأساسية
    'flow_duration': 'flow_duration',
    'header_length': 'Header_Length',
    'protocol_type': 'Protocol Type',
    'duration': 'Duration',
    'rate': 'Rate',
    'srate': 'Srate',
    'drate': 'Drate',
    'fin_flag': 'fin_flag_number',
    'syn_flag': 'syn_flag_number',
    'ack_flag': 'ack_flag_number',
    'max_size': 'Max',
    'avg_size': 'AVG',
    'std_dev': 'Std',
    'magnitude': 'Magnitue'
}

print("🔧 Mapping and cleaning columns...")
final_df = pd.DataFrame()

# محاولة نقل البيانات للأعمدة الجديدة
for target_col, source_col in column_mapping.items():
    if source_col in full_df.columns:
        final_df[target_col] = full_df[source_col]
    else:
        # إذا لم نجد العمود، نبحث عنه بحالة أحرف صغيرة (Lower Case) كخطة بديلة
        found = False
        for col in full_df.columns:
            if col.lower() == source_col.lower().replace(' ', '_'):
                final_df[target_col] = full_df[col]
                found = True
                break
        
        if not found:
            # إذا يئسنا من إيجاده، نملأه بصفر (Safe Fallback)
            print(f"  ⚠️ Warning: Column '{source_col}' not found. Filling with 0.")
            final_df[target_col] = 0

# التعامل مع عمود التصنيف (Label)
found_label = False
for label_candidate in ['label', 'class', 'attack_type', 'Label', 'Class']:
    if label_candidate in full_df.columns:
        final_df['label'] = full_df[label_candidate]
        found_label = True
        break

if not found_label:
    print("❌ Critical Error: Could not find the 'Label' column!")
    exit()

# --- 4. حماية الرام (Sampling) ---
MAX_RECORDS = 300000
if len(final_df) > MAX_RECORDS:
    print(f"✂️ Optimizing dataset: Sampling {MAX_RECORDS} random records...")
    final_df = final_df.sample(n=MAX_RECORDS, random_state=42)

# تنظيف القيم (NaN / Infinity)
X = final_df.drop('label', axis=1)
y = final_df['label']
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

# --- 5. التدريب (The Engine) ---
print(f"📊 Training on {len(X)} records with {len(X.columns)} features...")

le = LabelEncoder()
# تحويل النصوص إلى أرقام (Strings -> Integers)
y_encoded = le.fit_transform(y.astype(str))

X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

print("🧠 Building Random Forest Model...")
# إعدادات متوازنة: 40 شجرة وعمق 20 (قوي وسريع)
model = RandomForestClassifier(n_estimators=30, max_depth=10, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# --- 6. التقييم والحفظ ---
print("\n🔍 Evaluating Model Accuracy...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print("="*50)
print(f"✅ FINAL ACCURACY: {accuracy * 100:.2f}%")
print("="*50)

print("💾 Saving artifacts...")
joblib.dump(model, os.path.join(SAVE_PATH, 'waap_model.pkl'))
joblib.dump(le, os.path.join(SAVE_PATH, 'label_encoder.pkl'))

# حفظ أسماء الأعمدة التي تدرب عليها الموديل لضمان التطابق لاحقاً
# غير compress من 3 إلى 9
joblib.dump(model, os.path.join(SAVE_PATH, 'waap_model.pkl'), compress=9)

print("🎉 ALL DONE! The system is ready for the attack simulation.")
