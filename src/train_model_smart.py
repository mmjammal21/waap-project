import pandas as pd
import glob
import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# المسارات
DATA_FOLDER = '/home/malik/graduation_project/data/waap_dataset_2026'
MODEL_PATH = '/home/malik/graduation_project/data/waap_model.pkl'
ENCODER_PATH = '/home/malik/graduation_project/data/label_encoder.pkl'

print(f"📂 Looking for files in: {DATA_FOLDER}")

# البحث عن الملفات
csv_files = glob.glob(os.path.join(DATA_FOLDER, "part-*.csv"))
if not csv_files:
    print("❌ No files found!")
    exit()

# --- التعديل الجذري هنا ---
# سنقرأ ملفاً واحداً فقط ولن نقرأه كاملاً، سنأخذ أول 50 ألف سطر فقط
# هذا يضمن عدم امتلاء الرام مهما كان جهازك ضعيفاً
target_file = csv_files[0]
print(f"⏳ Reading lightweight sample from: {os.path.basename(target_file)}...")

df = pd.read_csv(target_file, nrows=50000) # قراءة 50 ألف سطر فقط

print(f"✅ Data Loaded: {len(df)} rows")

# تنظيف الأسماء
df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')

# تصحيح اسم Label إذا اختلف
for col in ['class', 'attack_type', 'label']:
    if col in df.columns:
        df.rename(columns={col: 'label'}, inplace=True)
        break

# اختيار الأعمدة
req_cols = ['flow_duration', 'header_length', 'protocol_type', 'duration', 'rate', 'label']
exist_cols = [c for c in req_cols if c in df.columns]
df = df[exist_cols].dropna()

# التدريب
print("⚙️ Training...")
X = df.drop(columns=['label'])
y = df['label']

le = LabelEncoder()
y_encoded = le.fit_transform(y)
joblib.dump(le, ENCODER_PATH)

model = RandomForestClassifier(n_estimators=10, random_state=42, n_jobs=-1)
model.fit(X, y_encoded)

joblib.dump(model, MODEL_PATH)
print(f"✅ SUCCESS! Model saved to: {MODEL_PATH}")
