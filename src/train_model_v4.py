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

print("🚀 Starting ULTIMATE AI Training (Expanded Features Mode)...")

# --- 2. تحميل البيانات ---
all_files = glob.glob(os.path.join(DATA_PATH, "*.csv"))
if not all_files:
    print("❌ No CSV files found!")
    exit()

# نأخذ 3 ملفات كعينة
selected_files = all_files[:3]
print(f"📂 Loading data from {len(selected_files)} files...")

df_list = []
for file in selected_files:
    try:
        # نقرأ 150 ألف سطر
        df = pd.read_csv(file, nrows=150000)
        df_list.append(df)
    except Exception as e:
        print(f"⚠️ Skipped {os.path.basename(file)}")

full_df = pd.concat(df_list, ignore_index=True)

# --- 3. خريطة الأعمدة الموسعة (The Secret Sauce) ---
# قمت بإضافة أهم الأعمدة الإحصائية الموجودة في صورتك
column_mapping = {
    # الخصائص الأساسية
    'flow_duration': 'flow_duration',
    'header_length': 'Header_Length',
    'protocol_type': 'Protocol Type',
    'duration': 'Duration',
    'rate': 'Rate',
    
    # الخصائص الإضافية (لرفع الدقة)
    'srate': 'Srate',       # Source Rate
    'drate': 'Drate',       # Destination Rate
    'fin_flag': 'fin_flag_number',
    'syn_flag': 'syn_flag_number',
    'ack_flag': 'ack_flag_number',
    'max_size': 'Max',      # Maximum packet size
    'avg_size': 'AVG',      # Average packet size
    'std_dev': 'Std',       # Standard Deviation (مهم جداً)
    'magnitude': 'Magnitue' # (مكتوبة هكذا في الداتا تبعتك)
}

print("🔧 Mapping extended features...")
final_df = pd.DataFrame()

# نقل البيانات للأعمدة الصحيحة
for target_col, source_col in column_mapping.items():
    if source_col in full_df.columns:
        final_df[target_col] = full_df[source_col]
    else:
        # إذا لم نجد عموداً ثانوياً، نملأه بصفر بدلاً من إيقاف البرنامج
        print(f"⚠️ Note: Column {source_col} not found. Filling with 0.")
        final_df[target_col] = 0

# إضافة Label
if 'label' in full_df.columns:
    final_df['label'] = full_df['label']
else:
    print("❌ Error: 'label' column not found!")
    exit()

# --- 4. حماية الرام ---
if len(final_df) > 300000:
    print("✂️ Optimizing dataset size for RAM safety...")
    final_df = final_df.sample(n=300000, random_state=42)

X = final_df.drop('label', axis=1)
y = final_df['label']
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

# --- 5. التدريب ---
print(f"📊 Training on {len(X)} records with {len(X.columns)} features...")

le = LabelEncoder()
y_encoded = le.fit_transform(y.astype(str))

X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

print("🧠 Training Random Forest (High Precision)...")
model = RandomForestClassifier(n_estimators=50, max_depth=25, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# --- 6. النتيجة ---
print("\n🔍 Evaluating...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print("="*40)
print(f"✅ MODEL ACCURACY: {accuracy * 100:.2f}%")
print("="*40)

print("\n💾 Saving Enhanced Model...")
# حفظ الموديل الجديد
joblib.dump(model, os.path.join(SAVE_PATH, 'waap_model.pkl'))
# حفظ المعالج (Encoder)
joblib.dump(le, os.path.join(SAVE_PATH, 'label_encoder.pkl'))
print("🎉 SYSTEM UPGRADED! Your AI is now much smarter.")
