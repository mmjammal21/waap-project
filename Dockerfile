FROM python:3.10-slim
WORKDIR /app

# 1. تثبيت أدوات النظام (بما فيها curl الذي أضفته مؤخراً)
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 2. نسخ ملف المتطلبات وتثبيته (هذا هو السطر المفقود في صورتك)
COPY requirements.txt .
RUN pip install --no-cache-dir --default-timeout=1000 -r requirements.txt

# 3. نسخ باقي ملفات المشروع
COPY . .

EXPOSE 5000

# 4. أمر التشغيل
CMD ["gunicorn", "--bind", "0.0.0.0:10000", "src.app_final:app"]
