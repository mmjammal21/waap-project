import sqlite3
import hashlib
import os

# تحديد المسارات (هذا الكود في src وقاعدة البيانات ستكون في data)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "data")
DB_PATH = os.path.join(DATA_DIR, "users.db")

# التأكد من وجود مجلد data (إذا لم يكن موجوداً سيتم إنشاؤه)
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

def hash_password(password):
    """تشفير كلمة المرور بـ SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    # الاتصال بالقاعدة (سيتم إنشاء ملف users.db تلقائياً)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # إنشاء جدول المستخدمين (نظام حماية SQL Injection)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

    # إضافة المستخدمين (تشفير SHA-256)
    hashed_pass = hash_password('Just@1999')
    users = [
        ('admin', hashed_pass, 'Administrator'),
        ('user', hashed_pass, 'Regular User')
    ]

    try:
        cursor.executemany('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', users)
        conn.commit()
        print(f"--- SUCCESS ---")
        print(f"Database File Created at: {DB_PATH}")
        print(f"Admin & User added with SHA-256 hashing.")
    except sqlite3.IntegrityError:
        print("--- NOTICE ---")
        print("Database already exists and users are already there.")
    
    conn.close()

if __name__ == "__main__":
    init_db()
