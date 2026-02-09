import pandas as pd
import glob
import os

# مسار البيانات
DATA_PATH = '/home/malik/graduation_project/data/waap_dataset_2026/'

# العثور على أول ملف فقط
files = glob.glob(os.path.join(DATA_PATH, "*.csv"))

if files:
    print(f"📂 Reading columns from: {os.path.basename(files[0])}")
    df = pd.read_csv(files[0], nrows=1) # قراءة السطر الأول فقط
    print("\n👇 PLEASE COPY THESE COLUMNS 👇")
    print("------------------------------------------------")
    print(df.columns.tolist())
    print("------------------------------------------------")
else:
    print("❌ No CSV files found.")
