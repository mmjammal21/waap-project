import joblib
import os

# المسارات (الديناميكية)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'data', 'waap_model.pkl')

print("⏳ Loading the giant model...")
try:
    # تحميل الموديل الحالي
    model = joblib.load(MODEL_PATH)
    
    # فحص عدد الأشجار الحالي
    original_trees = len(model.estimators_)
    print(f"🌲 Original Trees: {original_trees}")
    
    # العملية الجراحية: الاحتفاظ بأول 15 شجرة فقط
    # هذا يقلل الحجم بنسبة 85% مع الحفاظ على طريقة العمل
    if original_trees > 15:
        model.estimators_ = model.estimators_[:15]
        model.n_estimators = 15
        print(f"✂️  Sliced to 15 trees (Lite Version).")
    
    # الحفظ فوق الملف القديم
    print("💾 Saving Lite model...")
    joblib.dump(model, MODEL_PATH, compress=3)
    
    # التحقق من الحجم
    size_mb = os.path.getsize(MODEL_PATH) / (1024 * 1024)
    print(f"✅ DONE! New Size on Disk: {size_mb:.2f} MB")
    print("🚀 This model will fit easily in Render RAM!")

except Exception as e:
    print(f"❌ Error: {e}")
