from flask import request
import re
import time
import os
from rules import RULES
from database import log_attack, get_client_ip

# Import the enhanced detector (now with ML and statistical analysis)
from ultra_anomaly_detection import EnhancedUltraAnomalyDetector as AnomalyDetector

SAFE_PATHS = ['/login', '/', '/logout', '/favicon.ico', '/monitor', '/api/logs', '/dashboard', '/tools', '/user-management', '/anomaly-testing']

# Administrative endpoints that bypass anomaly detection when authenticated
# These are legitimate operations that may contain SQL/command keywords
ADMIN_ENDPOINTS = [
    '/api/db/clear',     # Database log clearing
    '/api/db/backup',    # Database backup
    '/api/db/export',    # CSV export
    '/api/db/stats',     # Database statistics
    '/api/users',        # Get all users
    '/api/users/create', # Create new user
    '/api/anomaly/test', # Anomaly detection testing
]

# Initialize enhanced anomaly detector with ML enabled
anomaly_detector = AnomalyDetector(enable_ml=True)

# Try to load pre-trained model
model_loaded = False
if os.path.exists('anomaly_detector_model.pkl'):
    try:
        anomaly_detector.load_model('anomaly_detector_model.pkl')
        model_loaded = True
        print("[WAF] ✅ Loaded pre-trained anomaly detection model")
    except Exception as e:
        print(f"[WAF] ⚠️  Could not load model: {e}")
        print("[WAF] Will train with default samples")

# If no model loaded, train with basic samples
if not model_loaded:
    print("[WAF] Training anomaly detector with default samples...")
    
    # Try to load from CSV if available
    csv_loaded = False
    if os.path.exists('datasets/csic2010/CSIC_2010.csv'):
        try:
            import csv
            normal_samples = []
            
            with open('datasets/csic2010/CSIC_2010.csv', 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                
                for row in reader:
                    if len(row) >= 3 and row[0].strip() == 'Normal':
                        url = row[-1].strip()
                        normal_samples.append({
                            'ip': '127.0.0.1',
                            'path': '',
                            'payload': url,
                            'timestamp': time.time()
                        })
                        
                        if len(normal_samples) >= 2000:
                            break
            
            if len(normal_samples) >= 100:
                anomaly_detector.train_baseline(normal_samples)
                csv_loaded = True
                print(f"[WAF] ✅ Trained on {len(normal_samples)} samples from CSIC dataset")
                
                # Save the model for future use
                try:
                    anomaly_detector.save_model('anomaly_detector_model.pkl')
                    print("[WAF] ✅ Model saved to anomaly_detector_model.pkl")
                except:
                    pass
        except Exception as e:
            print(f"[WAF] ⚠️  Could not load CSIC dataset: {e}")
    
    # Fallback to default samples if CSV not loaded
    if not csv_loaded:
        normal_samples = [
            {'ip': '127.0.0.1', 'path': '/login', 'payload': 'username=user&password=pass', 'timestamp': time.time()},
            {'ip': '127.0.0.1', 'path': '/dashboard', 'payload': '', 'timestamp': time.time()},
            {'ip': '127.0.0.1', 'path': '/monitor', 'payload': '', 'timestamp': time.time()},
            {'ip': '127.0.0.1', 'path': '/tools', 'payload': '', 'timestamp': time.time()},
            {'ip': '127.0.0.1', 'path': '/api/logs', 'payload': 'limit=50', 'timestamp': time.time()},
            {'ip': '127.0.0.1', 'path': '/search', 'payload': 'q=test', 'timestamp': time.time()},
            {'ip': '127.0.0.1', 'path': '/profile', 'payload': 'id=123', 'timestamp': time.time()},
            {'ip': '127.0.0.1', 'path': '/settings', 'payload': 'theme=dark', 'timestamp': time.time()},
        ] * 25  # Duplicate to get ~200 samples
        
        anomaly_detector.train_baseline(normal_samples)
        print(f"[WAF] ✅ Trained on {len(normal_samples)} default samples")

print(f"[WAF] Anomaly Detector Ready:")
print(f"  - ML Enabled: {anomaly_detector.enable_ml}")
print(f"  - Trained: {anomaly_detector.trained}")
print(f"  - Features: 35+")
print(f"  - Layers: Pattern + Anomaly (ML+Stats+Rules) + Behavioral")

def waf_middleware(app):
    @app.before_request
    def inspect_request():
        # Skip monitoring for safe paths (GET only, no query params)
        if request.path in SAFE_PATHS and request.method == 'GET' and not request.args:
            return
        
        # Skip static files
        if request.path.startswith('/static'):
            return
        
        # Skip admin endpoints if user is authenticated
        # These are legitimate operations that may contain SQL/command keywords
        if request.path in ADMIN_ENDPOINTS:
            from flask import session
            if 'user_id' in session:
                # Authenticated admin operation - bypass all WAF checks
                return
            
        try:
            get_data = request.args.to_dict(flat=True)
            post_data = request.form.to_dict(flat=True)
        except Exception:
            get_data, post_data = {}, {}

        data = str(get_data) + str(post_data)
        data += str(request.headers.get('User-Agent', '')) + str(request.path)

        # ===========================
        # LAYER 1: PATTERN MATCHING
        # ===========================
        for attack_type, patterns in RULES.items():
            for i, pattern in enumerate(patterns):
                try:
                    # Compile the pattern first to catch errors early
                    compiled_pattern = re.compile(pattern, re.IGNORECASE)
                    if compiled_pattern.search(data):
                        ip = get_client_ip(request)
                        user_agent = request.headers.get('User-Agent', 'Unknown')
                        log_attack(ip, attack_type, data[:500], request.path, user_agent)
                        print(f"[WAF BLOCKED - Layer 1] {attack_type} from {ip}")
                        print(f"  Pattern matched: {pattern[:50]}...")
                        return "⚠️ Request blocked: suspicious activity detected.", 403
                except re.error as e:
                    # Malformed regex pattern - log it but continue checking other patterns
                    print(f"[WAF ERROR] Invalid regex pattern in {attack_type}[{i}]: {e}")
                    print(f"  Pattern: {pattern[:100]}")
                    # Don't crash - continue to next pattern
                    continue
                except Exception as e:
                    # Other errors - log and continue
                    print(f"[WAF ERROR] Error checking pattern {attack_type}[{i}]: {e}")
                    continue
        
        # ===========================
        # LAYER 2: ENHANCED ANOMALY DETECTION
        # ===========================
        if anomaly_detector.trained:
            request_data = {
                'ip': get_client_ip(request),
                'path': request.path,
                'payload': data,
                'timestamp': time.time()
            }
            
            # Use adaptive threshold (None = auto-select based on endpoint)
            # The enhanced detector will choose the right threshold for this path
            is_anomalous, score, details = anomaly_detector.is_anomalous(
                request_data, 
                threshold=None  # Use adaptive threshold
            )
            
            if is_anomalous:
                ip = get_client_ip(request)
                user_agent = request.headers.get('User-Agent', 'Unknown')
                
                # Build detailed log
                breakdown = details.get('breakdown', {})
                reasons = ', '.join([f"{k}" for k in list(breakdown.keys())[:3]])
                
                payload = f"Anomaly Score: {score:.0f} (threshold: {details.get('threshold', 25)}) | {reasons}"
                log_attack(ip, 'Anomalous Behavior', payload[:500], request.path, user_agent)
                
                print(f"[WAF BLOCKED - Layer 2] Anomalous behavior from {ip}")
                print(f"  Score: {score:.0f} / Threshold: {details.get('threshold', 25)}")
                print(f"  Top reasons: {reasons}")
                
                if anomaly_detector.enable_ml:
                    print(f"  ML Enabled: Yes")
                
                return "⚠️ Request blocked: suspicious activity detected.", 403
        
        # Otherwise allow request to proceed