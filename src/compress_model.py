import joblib
import os

# المسارات
OLD_MODEL_PATH = '/home/malik/graduation_project/data/waap_model.pkl'
NEW_MODEL_PATH = '/home/malik/graduation_project/data/waap_model_compressed.pkl'

print("📦 Loading original model (this might take a few seconds)...")
try:
    model = joblib.load(OLD_MODEL_PATH)
    print(f"✅ Loaded! Original Size: {os.path.getsize(OLD_MODEL_PATH) / (1024*1024):.2f} MB")

    print("🗜️ Compressing and saving...")
    # هنا السحر: compress=3 يضغط الملف بقوة
    joblib.dump(model, NEW_MODEL_PATH, compress=3)

    new_size = os.path.getsize(NEW_MODEL_PATH) / (1024*1024)
    print(f"🎉 Done! New Size: {new_size:.2f} MB")

    # استبدال القديم بالجديد
    os.remove(OLD_MODEL_PATH)
    os.rename(NEW_MODEL_PATH, OLD_MODEL_PATH)
    print("🔄 Replaced old model with the compressed version.")

except Exception as e:
    print(f"❌ Error: {e}")
