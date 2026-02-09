from flask import Flask, request, render_template_string, jsonify, session, redirect, url_for
import pandas as pd
import joblib
import redis
import os
from datetime import datetime, timedelta
from urllib.parse import unquote


# --- 1. إعدادات النظام (Dynamic Paths) ---

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')

MODEL_PATH = os.path.join(DATA_DIR, 'waap_model.pkl')
LABEL_ENCODER_PATH = os.path.join(DATA_DIR, 'label_encoder.pkl')
LOG_FILE = os.path.join(DATA_DIR, 'waf_logs.txt')

app = Flask(__name__)  
app.secret_key = 'malik_secret_key_123'

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')

# التأكد من وجود مجلد الداتا، وإن لم يكن موجوداً ينشئه (للمنطقية)
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# --- 2. تهيئة المحرك ---

# --- التعديل الجديد للاتصال بـ Redis ---
# هذا الكود يعمل محلياً وعلى الكلاود تلقائياً
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
try:
    r = redis.from_url(redis_url, decode_responses=True)
    try: r.ping()
    except: r = None
    
    model = joblib.load(MODEL_PATH)
    le = joblib.load(LABEL_ENCODER_PATH)
    print("✅ [SYSTEM READY] Engine Active.")
except Exception as e:
    print(f"❌ [ERROR] {e}")
    r = None
    pass

# --- 3. التسجيل (توقيت الأردن UTC+3) ---
def log_event(ip, url, threat, action):
    jordan_time = datetime.utcnow() + timedelta(hours=3)
    timestamp = jordan_time.strftime("%Y-%m-%d %H:%M:%S")
    
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp},{ip},{url},{threat},{action}\n")

# --- 4. القوالب (UI Templates) ---

LOGIN_PAGE_HTML = """
<!DOCTYPE html><html lang="en"><head><title>WAAP | Secure Login</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
<style>
    body { background: linear-gradient(135deg, #141E30, #243B55); height: 100vh; display: flex; align-items: center; justify-content: center; font-family: 'Segoe UI', sans-serif; }
    .login-card { background: rgba(255, 255, 255, 0.05); backdrop-filter: blur(10px); padding: 40px; border-radius: 20px; border: 1px solid rgba(255,255,255,0.1); width: 100%; max-width: 400px; text-align: center; color: white; box-shadow: 0 15px 35px rgba(0,0,0,0.5); }
    .form-control { background: rgba(255, 255, 255, 0.1); border: none; color: white; padding: 12px; margin-bottom: 15px; }
    .form-control::placeholder { color: rgba(255, 255, 255, 0.5); }
    .form-control:focus { background: rgba(255, 255, 255, 0.2); color: white; box-shadow: none; outline: none; }
    .btn-login { background: #00c6ff; background: -webkit-linear-gradient(to right, #0072ff, #00c6ff); background: linear-gradient(to right, #0072ff, #00c6ff); color: white; font-weight: bold; padding: 12px; width: 100%; border-radius: 8px; border: none; transition: 0.3s; margin-top: 10px;}
    .btn-login:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0, 198, 255, 0.4); }
</style></head>
<body>
    <div class="login-card">
        <i class="fas fa-shield-halved fa-4x mb-4" style="color: #00c6ff;"></i>
        <h2 class="mb-1 fw-bold">WAAP Gateway</h2>
        <p class="mb-4 opacity-75">Secure Access Portal</p>
        {% if error %}<div class="alert alert-danger py-2 small">{{ error }}</div>{% endif %}
        <form action="/login" method="POST">
            <input type="text" name="user" class="form-control" placeholder="Username" required>
            <input type="password" name="pass" class="form-control" placeholder="Password" required>
            <button class="btn btn-login">AUTHENTICATE</button>
        </form>
        <div class="mt-4 small opacity-50"><i class="fas fa-lock me-1"></i> Protected by AI & Signatures</div>
    </div>
</body></html>
"""

USER_HOME_HTML = """
<!DOCTYPE html><html lang="en"><head><title>My Bank</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
<style> 
    body { background: #f0f2f5; font-family: 'Segoe UI', sans-serif; } 
    .navbar { background: #ffffff; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
    .nav-link { color: #333; font-weight: 600; }
    
    .credit-card { 
        background: linear-gradient(135deg, #11998e, #38ef7d); 
        color: white; border-radius: 20px; padding: 25px; 
        box-shadow: 0 10px 20px rgba(17, 153, 142, 0.3); 
        position: relative; overflow: hidden; height: 220px;
        display: flex; flex-direction: column; justify-content: space-between;
    }
    .credit-card::before { content: ''; position: absolute; top: -50px; right: -50px; width: 150px; height: 150px; background: rgba(255,255,255,0.1); border-radius: 50%; }
    .card-number { letter-spacing: 2px; font-size: 1.4rem; margin-top: 10px;}
    .card-holder { font-size: 0.9rem; text-transform: uppercase; opacity: 0.8; }
    
    .quick-action-btn { background: white; border: none; padding: 20px; border-radius: 15px; width: 100%; text-align: center; transition: 0.3s; box-shadow: 0 2px 10px rgba(0,0,0,0.02); cursor: pointer; color: #555; }
    .quick-action-btn:hover { transform: translateY(-5px); box-shadow: 0 5px 15px rgba(0,0,0,0.1); color: #11998e; }
    .icon-box { font-size: 1.5rem; margin-bottom: 10px; display: block; }
    
    .transaction-card { border: none; border-radius: 15px; box-shadow: 0 2px 15px rgba(0,0,0,0.03); background: white; }
</style>
</head><body>

<nav class="navbar navbar-expand-lg navbar-light px-4 py-3 mb-4">
    <div class="container-fluid">
        <a class="navbar-brand fw-bold text-primary" href="#"><i class="fas fa-university me-2"></i> NS Bank</a>
        <div class="d-flex align-items-center">
            <div class="me-3 text-end d-none d-md-block">
                <div class="fw-bold small">{{ user }}</div>
                <div class="text-muted small" style="font-size: 0.75rem;">Premium Account</div>
            </div>
            <div class="bg-light rounded-circle p-2 me-3"><i class="fas fa-user text-secondary"></i></div>
            <a href="/logout" class="btn btn-outline-danger btn-sm rounded-pill px-3"><i class="fas fa-sign-out-alt"></i></a>
        </div>
    </div>
</nav>

<div class="container">
    <div class="row g-4">
        <div class="col-lg-4">
            <div class="credit-card mb-4">
                <div class="d-flex justify-content-between align-items-center">
                    <span class="badge bg-white text-success bg-opacity-75">Active</span>
                    <i class="fab fa-cc-visa fa-2x"></i>
                </div>
                <div class="mt-2">
                    <small class="opacity-75">Total Balance</small>
                    <h1 class="fw-bold">$12,450.00</h1>
                </div>
                <div>
                    <div class="card-number">**** **** **** 8821</div>
                    <div class="d-flex justify-content-between mt-3">
                        <span class="card-holder">{{ user }}</span>
                        <span class="card-holder">EXP 09/28</span>
                    </div>
                </div>
            </div>
            
            <div class="row g-2">
                <div class="col-4">
                    <div class="quick-action-btn">
                        <i class="fas fa-paper-plane icon-box text-primary"></i> <small>Transfer</small>
                    </div>
                </div>
                <div class="col-4">
                    <div class="quick-action-btn">
                        <i class="fas fa-file-invoice-dollar icon-box text-warning"></i> <small>Bills</small>
                    </div>
                </div>
                <div class="col-4">
                    <div class="quick-action-btn">
                        <i class="fas fa-qrcode icon-box text-dark"></i> <small>Scan</small>
                    </div>
                </div>
            </div>
        </div>

        <div class="col-lg-8">
            <div class="transaction-card p-4 h-100">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h5 class="fw-bold m-0">Recent Transactions</h5>
                    <button class="btn btn-sm btn-light text-muted">View All</button>
                </div>
                <div class="table-responsive">
                    <table class="table table-hover align-middle">
                        <thead class="table-light small text-muted"><tr><th>Merchant</th><th>Category</th><th>Date</th><th class="text-end">Amount</th></tr></thead>
                        <tbody>
                            <tr>
                                <td><div class="d-flex align-items-center"><div class="bg-danger bg-opacity-10 p-2 rounded me-3 text-danger"><i class="fab fa-netflix"></i></div><strong>Netflix</strong></div></td>
                                <td class="text-muted small">Entertainment</td>
                                <td class="text-muted small">Today, 10:30 AM</td>
                                <td class="text-end text-danger fw-bold">-$15.00</td>
                            </tr>
                            <tr>
                                <td><div class="d-flex align-items-center"><div class="bg-success bg-opacity-10 p-2 rounded me-3 text-success"><i class="fas fa-building"></i></div><strong>Salary</strong></div></td>
                                <td class="text-muted small">Income</td>
                                <td class="text-muted small">Yesterday</td>
                                <td class="text-end text-success fw-bold">+$2,500.00</td>
                            </tr>
                            <tr>
                                <td><div class="d-flex align-items-center"><div class="bg-warning bg-opacity-10 p-2 rounded me-3 text-warning"><i class="fab fa-amazon"></i></div><strong>Amazon AWS</strong></div></td>
                                <td class="text-muted small">Services</td>
                                <td class="text-muted small">Feb 01, 2026</td>
                                <td class="text-end text-danger fw-bold">-$45.00</td>
                            </tr>
                            <tr>
                                <td><div class="d-flex align-items-center"><div class="bg-info bg-opacity-10 p-2 rounded me-3 text-info"><i class="fas fa-shopping-basket"></i></div><strong>City Market</strong></div></td>
                                <td class="text-muted small">Groceries</td>
                                <td class="text-muted small">Jan 28, 2026</td>
                                <td class="text-end text-danger fw-bold">-$55.50</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div></body></html>
"""

BLOCK_PAGE_HTML = """
<!DOCTYPE html><html lang="en"><head><title>Access Denied</title>
<style>
    body { background-color: #0d0d0d; color: #ff3333; height: 100vh; display: flex; align-items: center; justify-content: center; font-family: 'Courier New', monospace; text-align: center; margin: 0; }
    .box { border: 1px solid #ff3333; padding: 40px; background: rgba(20, 0, 0, 0.9); box-shadow: 0 0 30px rgba(255, 0, 0, 0.2); max-width: 600px; width: 90%; }
    h1 { font-size: 3rem; margin: 0 0 20px 0; letter-spacing: 2px; text-transform: uppercase; }
    .details { border-top: 1px solid #330000; margin-top: 20px; padding-top: 20px; text-align: left; }
    .row { display: flex; justify-content: space-between; margin-bottom: 10px; color: #ff8888; }
    .val { color: #fff; font-weight: bold; }
</style></head>
<body>
    <div class="box">
        <h1>⛔ Request Blocked</h1>
        <p>Malicious activity detected by WAAP Gateway.</p>
        <div class="details">
            <div class="row"><span>Reason:</span> <span class="val">{{ reason }}</span></div>
            <div class="row"><span>Event ID:</span> <span class="val">{{ ip_hash }}</span></div>
            <div class="row"><span>Your IP:</span> <span class="val">Logged & Reported</span></div>
        </div>
    </div>
</body></html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html><html lang="en"><head><title>Admin Dashboard</title>
<meta http-equiv="refresh" content="5">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
    body { background: #f4f7fa; font-family: 'Segoe UI', sans-serif; }
    .sidebar { height: 100vh; background: #2c3e50; color: white; position: fixed; width: 240px; padding: 20px; z-index: 100; box-shadow: 2px 0 5px rgba(0,0,0,0.05); }
    .sidebar h4 { font-weight: 700; letter-spacing: 1px; font-size: 1.2rem; margin-bottom: 30px; color: #ecf0f1; }
    .sidebar a { display: block; padding: 12px 15px; color: #bdc3c7; text-decoration: none; border-radius: 8px; margin-bottom: 5px; transition: 0.2s; font-size: 0.95rem; }
    .sidebar a:hover, .sidebar a.active { color: #fff; background: rgba(255,255,255,0.1); }
    .sidebar a.active { border-left: 4px solid #3498db; }
    
    .main { margin-left: 240px; padding: 30px; }
    .stat-card { background: white; border: none; border-radius: 12px; padding: 20px; box-shadow: 0 2px 15px rgba(0,0,0,0.03); transition: 0.3s; }
    .stat-card:hover { transform: translateY(-3px); box-shadow: 0 5px 20px rgba(0,0,0,0.06); }
    .stat-title { color: #7f8c8d; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; margin-bottom: 10px; }
    .stat-val { font-size: 1.8rem; font-weight: 700; color: #2c3e50; }
    .chart-container { position: relative; height: 250px; width: 100%; display: flex; justify-content: center; }
</style></head>
<body>
<div class="sidebar">
    <h4><i class="fas fa-shield-alt me-2"></i>WAAP ADMIN</h4>
    <a href="/dashboard" class="active"><i class="fas fa-chart-pie me-3"></i>Dashboard</a>
    <a href="/logs"><i class="fas fa-file-contract me-3"></i>Audit Logs</a>
    <a href="/user_home" target="_blank"><i class="fas fa-external-link-alt me-3"></i>Live Site</a>
    <div style="margin-top: auto; padding-top: 50px;">
        <a href="/logout" class="text-danger"><i class="fas fa-sign-out-alt me-3"></i>Logout</a>
    </div>
</div>

<div class="main">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h3 class="fw-bold text-dark m-0">Security Overview</h3>
        <span class="badge bg-white text-muted border px-3 py-2 shadow-sm"><i class="far fa-clock me-1"></i> Live Monitor</span>
    </div>

    <div class="row g-4 mb-4">
        <div class="col-md-3">
            <div class="stat-card border-start border-4 border-success">
                <div class="stat-title">Allowed Requests</div>
                <div class="d-flex justify-content-between align-items-end">
                    <div class="stat-val">{{ stats['ALLOW'] }}</div>
                    <i class="fas fa-check-circle fa-2x text-success opacity-25"></i>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="stat-card border-start border-4 border-danger">
                <div class="stat-title">Blocked Threats</div>
                <div class="d-flex justify-content-between align-items-end">
                    <div class="stat-val">{{ stats['BLOCK'] }}</div>
                    <i class="fas fa-ban fa-2x text-danger opacity-25"></i>
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="stat-card">
                <div class="row align-items-center">
                    <div class="col-6">
                        <div class="stat-title">Threat Distribution</div>
                        <div class="small text-muted mb-2"><i class="fas fa-circle text-warning me-1"></i> SQLi & XSS</div>
                        <div class="small text-muted mb-2"><i class="fas fa-circle text-danger me-1"></i> DDoS Attacks</div>
                        <div class="small text-muted"><i class="fas fa-circle text-info me-1"></i> AI Anomalies</div>
                    </div>
                    <div class="col-6">
                        <div class="chart-container">
                            <canvas id="chart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="card border-0 shadow-sm rounded-3 overflow-hidden">
        <div class="card-header bg-white py-3 border-bottom">
            <h6 class="m-0 fw-bold text-dark"><i class="fas fa-satellite-dish me-2 text-primary"></i> Real-time Traffic Feed (Last 15)</h6>
        </div>
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
                <thead class="bg-light"><tr><th class="ps-4">Time</th><th>Source IP</th><th>Detection Type</th><th>Status</th></tr></thead>
                <tbody>
                    {% for log in logs %}
                    <tr>
                        <td class="ps-4 text-muted small">{{ log.time }}</td>
                        <td class="fw-bold text-dark font-monospace">{{ log.ip }}</td>
                        <td>
                            {% if "Clean" in log.threat %} <span class="badge bg-success bg-opacity-10 text-success rounded-pill px-3">Normal</span>
                            {% elif "DDoS" in log.threat or "Rate" in log.threat %} 
                                <span class="badge bg-dark text-white border border-danger" style="width: 100px;">⚡ DDoS</span>
                            {% elif "SQL" in log.threat %} 
                                <span class="badge bg-danger text-white" style="width: 100px;">💉 SQLi</span>
                            {% elif "XSS" in log.threat %} 
                                <span class="badge bg-warning text-dark" style="width: 100px;">📜 XSS</span>
                            {% elif "Unauthorized" in log.threat %} 
                                <span class="badge bg-secondary text-white" style="width: 100px;">🔒 Auth</span>
                            {% else %} 
                                <span class="badge bg-info text-dark" style="width: 100px;">🤖 AI</span>
                            {% endif %}
                        </td>
                        <td>
                            {% if log.action == "ALLOW" %} <i class="fas fa-check text-success"></i>
                            {% else %} <i class="fas fa-times text-danger"></i>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>

<script>
    const ctx = document.getElementById('chart').getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Normal', 'SQLi', 'XSS', 'DDoS', 'AI'],
            datasets: [{
                data: [{{ stats['ALLOW'] }}, {{ stats['SQLi'] }}, {{ stats['XSS'] }}, {{ stats['DDoS'] }}, {{ stats['AI'] }}],
                backgroundColor: ['#2ecc71', '#e74c3c', '#f1c40f', '#34495e', '#3498db'],
                borderWidth: 0,
                hoverOffset: 10
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(0,0,0,0.8)',
                    padding: 10,
                    callbacks: {
                        label: function(context) {
                            let label = context.label || '';
                            if (label) { label += ': '; }
                            let value = context.raw;
                            let total = context.chart._metasets[context.datasetIndex].total;
                            let percentage = Math.round((value / total) * 100) + '%';
                            return label + value + ' (' + percentage + ')';
                        }
                    }
                }
            },
            cutout: '70%'
        }
    });
</script></body></html>
"""

LOGS_PAGE_HTML = """
<!DOCTYPE html><html lang="en"><head><title>Audit Logs</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
<style>body{background:#f8f9fa; padding:30px;}</style>
</head><body>
    <div class="container bg-white p-4 rounded shadow">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h4 class="text-dark fw-bold m-0"><i class="fas fa-history me-2 text-primary"></i> Full Security Audit Logs</h4>
            <a href="/dashboard" class="btn btn-outline-primary btn-sm"><i class="fas fa-arrow-left me-2"></i> Dashboard</a>
        </div>
        <table class="table table-striped table-hover border">
            <thead class="table-dark"><tr><th>Time (JO)</th><th>IP Address</th><th>Path</th><th>Threat</th><th>Action</th></tr></thead>
            <tbody>
                {% for log in logs %}
                <tr>
                    <td>{{ log.time }}</td>
                    <td class="font-monospace">{{ log.ip }}</td>
                    <td class="text-muted small">{{ log.url }}</td>
                    <td><span class="badge bg-secondary">{{ log.threat }}</span></td>
                    <td><b>{{ log.action }}</b></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body></html>
"""

# --- 5. المنطق الأمني (كما هو بدون تعديل) ---
@app.before_request
def waap_pipeline():
    if request.path.startswith('/static') or request.path.startswith('/logout') or request.path.startswith('/favicon.ico'):
        return

    ip = request.remote_addr
    decoded_path = unquote(request.full_path).lower() if request.full_path else ""

    if r:
        try:
            req_count = r.incr(ip)
            if req_count == 1: r.expire(ip, 60)
            if req_count > 100:
                log_event(ip, request.path, "Rate Limit (DDoS)", "BLOCK")
                return render_template_string(BLOCK_PAGE_HTML, reason="DDoS Attack Detected", ip_hash=hash(ip)), 429
        except: pass

    form_data = ""
    if request.method == 'POST':
        for key, value in request.form.items():
            form_data += f" {str(value).lower()}"
    full_payload = decoded_path + form_data

    signature_threat = None
    if "<script" in full_payload or "javascript:" in full_payload or "onerror" in full_payload:
        signature_threat = "XSS Attack Detected"
    elif "union" in full_payload or "select" in full_payload or " or 1=1" in full_payload or "'" in full_payload or "--" in full_payload or "#" in full_payload:
        signature_threat = "SQL Injection Detected"
    elif "/etc/passwd" in full_payload:
        signature_threat = "LFI Attack Detected"
        
    if signature_threat:
        log_event(ip, request.path, signature_threat, "BLOCK")
        return render_template_string(BLOCK_PAGE_HTML, reason=signature_threat, ip_hash=hash(ip)), 403

    try:
        features = pd.DataFrame([{'flow_duration': 0.5, 'header_length': len(str(request.headers)), 'protocol_type': 6, 'duration': 0.2, 'rate': req_count if 'req_count' in locals() else 1}])
        if hasattr(model, "feature_names_in_"):
            features = features[model.feature_names_in_]
        pred_idx = model.predict(features)[0]
        ai_verdict = le.inverse_transform([pred_idx])[0]
        
        if ai_verdict != "BenignTraffic":
            safe_pages = ['/', '/login', '/user_home', '/dashboard', '/logs']
            if request.path in safe_pages:
                log_event(ip, request.path, "AI Ignored (Safe Page)", "ALLOW")
            else:
                log_event(ip, request.path, f"AI Detected: {ai_verdict}", "BLOCK")
                return render_template_string(BLOCK_PAGE_HTML, reason=f"Traffic Anomaly ({ai_verdict})", ip_hash=hash(ip)), 403
    except: pass 

    if request.path in ['/dashboard', '/logs']:
        if 'user' not in session or session.get('role') != 'admin':
            log_event(ip, request.path, "Unauthorized Admin Access", "BLOCK")
            return render_template_string(BLOCK_PAGE_HTML, reason="Unauthorized Access (Admin Only)", ip_hash=hash(ip)), 403

    if request.path == '/user_home':
        if 'user' not in session:
            return redirect(url_for('login'))

    log_event(ip, request.path, "Clean Traffic", "ALLOW")

# --- 6. Routes ---

@app.route('/')
def index(): return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('user')
        password = request.form.get('pass')
        if user == 'admin' and password == 'admin123':
            session['user'] = 'admin'; session['role'] = 'admin'
            return redirect(url_for('dashboard'))
        elif user == 'user' and password == 'user123':
            session['user'] = 'user'; session['role'] = 'user'
            return redirect(url_for('user_home'))
        else:
            return render_template_string(LOGIN_PAGE_HTML, error="Invalid Credentials")
    return render_template_string(LOGIN_PAGE_HTML, error=None)

@app.route('/dashboard')
def dashboard():
    if session.get('role') != 'admin': 
        return render_template_string(BLOCK_PAGE_HTML, reason="Unauthorized", ip_hash=0), 403
    
    logs = []
    stats = {'ALLOW': 0, 'BLOCK': 0, 'XSS': 0, 'SQLi': 0, 'DDoS': 0, 'AI': 0}
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
            for line in lines:
                parts = line.strip().split(',')
                if len(parts) >= 5:
                    threat = parts[3]; action = parts[4]
                    if action == 'ALLOW': stats['ALLOW'] += 1
                    else: stats['BLOCK'] += 1
                    if "XSS" in threat: stats['XSS'] += 1
                    elif "SQL" in threat: stats['SQLi'] += 1
                    elif "Rate" in threat or "DDoS" in threat: stats['DDoS'] += 1
                    elif "AI" in threat: stats['AI'] += 1
            
            # 🔥 التعديل: عرض آخر 15 سجل فقط
            for line in reversed(lines[-15:]):
                p = line.strip().split(',')
                if len(p) >= 5: logs.append({'time':p[0], 'ip':p[1], 'threat':p[3], 'action':p[4]})
    
    return render_template_string(DASHBOARD_HTML, logs=logs, stats=stats)

@app.route('/logs')
def show_logs():
    if session.get('role') != 'admin': return "Forbidden", 403
    all_logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            for line in reversed(f.readlines()):
                p = line.strip().split(',')
                if len(p)>=5: all_logs.append({'time':p[0], 'ip':p[1], 'url':p[2], 'threat':p[3], 'action':p[4]})
    return render_template_string(LOGS_PAGE_HTML, logs=all_logs)

@app.route('/user_home')
def user_home():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template_string(USER_HOME_HTML, user=session['user'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
