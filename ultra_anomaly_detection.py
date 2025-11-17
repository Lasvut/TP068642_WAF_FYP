#!/usr/bin/env python3
"""
Enhanced Ultra-Aggressive Anomaly Detector
Multi-layered detection with ML, statistical analysis, and adaptive thresholds

Key Improvements:
1. Machine Learning layer (Isolation Forest)
2. Statistical anomaly detection (z-scores)
3. Adaptive thresholds per endpoint
4. N-gram analysis for obfuscation detection
5. Context-aware scoring
6. Improved false positive reduction
7. Feature normalization and scaling
8. Ensemble scoring combining multiple methods

Target: 85-95% detection rate with <5% false positives
"""

import re
import math
import numpy as np
from collections import Counter, defaultdict
from urllib.parse import urlparse, parse_qs, unquote
import pickle
import os

# Optional ML imports - graceful fallback if not available
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("⚠️  scikit-learn not available. ML features disabled. Install with: pip install scikit-learn")


class EnhancedUltraAnomalyDetector:
    """Enhanced detector with ML and advanced statistical analysis"""
    
    def __init__(self, enable_ml=True):
        self.baseline_stats = {}
        self.endpoint_thresholds = defaultdict(lambda: 25)  # Adaptive per endpoint
        self.trained = False
        self.enable_ml = enable_ml and ML_AVAILABLE
        
        # ML components
        self.isolation_forest = None
        self.scaler = None
        self.feature_importance = {}
        
        # Statistical baselines
        self.feature_distributions = {}  # Mean and std for each feature
        
        # Context tracking
        self.endpoint_patterns = defaultdict(lambda: {'count': 0, 'avg_score': 0})
        self.param_whitelist = set()
        
        # N-gram models for obfuscation detection
        self.normal_bigrams = Counter()
        self.normal_trigrams = Counter()
        
        # EXPANDED keyword lists (same as before, but optimized)
        self.sql_keywords = [
            'select', 'union', 'insert', 'update', 'delete', 'drop', 'create',
            'alter', 'exec', 'execute', 'script', 'concat', 'char', 'chr',
            'information_schema', 'sleep', 'benchmark', 'waitfor', 'delay',
            'substring', 'ascii', 'length', 'mid', 'count', 'group_concat',
            'load_file', 'into outfile', 'dumpfile',
            'having', 'order by', 'group by', 'limit', 'offset',
            'mysql', 'oracle', 'mssql', 'postgres', 'sysobjects', 'syscolumns',
            'cast', 'convert', 'hex', 'unhex', 'database(', 'version(',
            'user(', 'current_user', 'session_user', 'system_user',
        ]
        
        self.xss_keywords = [
            '<script', '</script', 'javascript:', 'onerror=', 'onload=',
            'onclick=', 'onmouseover=', 'onmouseout=', 'onfocus=', 'onblur=',
            '<iframe', '<object', '<embed', '<applet', '<meta', '<link',
            '<svg', '<img', '<body', '<input', '<form', '<button',
            'alert(', 'prompt(', 'confirm(', 'eval(', 'expression(',
            'document.', 'window.', 'parent.', 'top.', 'self.',
            'location.', 'document.cookie', 'document.write',
            'fromcharcode', 'innerhtml', 'outerhtml',
            'xmlhttprequest', 'fetch(', 'atob(', 'btoa(',
            'createelement', 'appendchild', 'setattribute',
        ]
        
        self.command_keywords = [
            'cat ', 'ls ', 'pwd', 'whoami', 'id', 'uname', 'ps', 'kill',
            '/etc/passwd', '/etc/shadow', '/bin/', '/usr/bin/', '/sbin/',
            'bash', 'sh ', 'zsh', 'csh', '/bin/sh', '/bin/bash',
            'cmd', 'powershell', 'net user', 'net localgroup',
            '|cat', '|ls', '|pwd', '|id', '|whoami',
            ';cat', ';ls', ';pwd', ';id', ';whoami',
            '&&cat', '&&ls', '&&pwd', '||cat', '||ls', '||pwd',
            'wget', 'curl', 'nc ', 'netcat', 'telnet', 'ssh', 'ftp',
            'rm ', 'mv ', 'cp ', 'chmod', 'chown', 'touch ', 'echo ',
        ]
        
        self.traversal_patterns = [
            '../', '..\\', '....', '..%2f', '..%5c', '%2e%2e',
            '/etc/', '/proc/', '/var/', '/usr/', '/root/',
            'c:\\', 'd:\\', 'c:/', 'd:/',
            'windows\\', 'winnt\\', 'system32\\',
            '%252e', '%c0%ae', '%e0%80%ae',
        ]
        
        self.suspicious_patterns = [
            "' or ", '" or ', '1=1', '1 = 1', "' and ", '" and ',
            "or 1=1", "or '1'='1", 'union select', 'union all select',
            'null,null', '0x', 'char(', 'chr(', 'concat(',
            '<script>', '</script>', 'alert(', 'prompt(', 'confirm(',
            'javascript:', 'onerror=', 'onload=', '<iframe',
            ';echo', '|echo', '&&echo', '||echo', '`echo', '$(echo',
            ';ls', '|ls', '&&ls', '||ls', ';cat', '|cat', '&&cat', '||cat',
            '%00', '\\0', '\\x00', '%0a', '%0d', '\\n', '\\r',
            '--', '/*', '*/', '<!--', '-->', '<?', '?>', '<%', '%>',
        ]
        
        self.suspicious_encodings = [
            '%27', '%22', '%3c', '%3e', '%3b', '%7c', '%26', '%60',
            '%28', '%29', '%2d%2d', '%2f%2a', '%2a%2f',
            '%00', '%0a', '%0d', '%09', '%20',
        ]
        
        self.suspicious_chars = ["'", '"', '<', '>', ';', '|', '&', '`', '$', '(', ')']
    
    def calculate_entropy(self, string):
        """Calculate Shannon entropy"""
        if not string:
            return 0.0
        counts = Counter(string)
        length = len(string)
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        return entropy
    
    def extract_ngrams(self, string, n=2):
        """Extract character n-grams"""
        return [string[i:i+n] for i in range(len(string)-n+1)]
    
    def calculate_ngram_anomaly_score(self, string):
        """Calculate anomaly score based on n-gram frequency"""
        if not self.normal_bigrams:
            return 0
        
        bigrams = self.extract_ngrams(string, 2)
        trigrams = self.extract_ngrams(string, 3)
        
        # Calculate how many n-grams are unseen in training
        unseen_bigrams = sum(1 for bg in bigrams if bg not in self.normal_bigrams)
        unseen_trigrams = sum(1 for tg in trigrams if tg not in self.normal_trigrams)
        
        bigram_score = (unseen_bigrams / max(len(bigrams), 1)) * 20
        trigram_score = (unseen_trigrams / max(len(trigrams), 1)) * 15
        
        return bigram_score + trigram_score
    
    def extract_features(self, request_data):
        """Extract comprehensive features with improved normalization"""
        url = request_data.get('payload', '') + request_data.get('path', '')
        decoded = unquote(url)
        decoded_lower = decoded.lower()
        url_lower = url.lower()
        
        features = {}
        
        # 1. Basic features
        features['length'] = len(url)
        features['decoded_length'] = len(decoded)
        features['entropy'] = self.calculate_entropy(url)
        
        # 2. Character counts (normalized by length)
        features['special_char_ratio'] = sum(1 for c in url if not c.isalnum() and c not in ['.', '/', '?', '&', '=', '-', '_']) / max(len(url), 1)
        features['percent_encoded_ratio'] = url.count('%') / max(len(url), 1)
        features['suspicious_char_count'] = sum(1 for char in self.suspicious_chars if char in decoded)
        
        # 3. Parameter features
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            features['num_params'] = len(params)
            features['max_param_length'] = max([len(str(v)) for v in params.values()], default=0)
            features['avg_param_length'] = sum([len(str(v)) for v in params.values()]) / max(len(params), 1) if params else 0
            
            # Unknown parameter detection
            param_keys = set(params.keys())
            features['unknown_params'] = len(param_keys - self.param_whitelist)
        except:
            features['num_params'] = 0
            features['max_param_length'] = 0
            features['avg_param_length'] = 0
            features['unknown_params'] = 0
        
        # 4. KEYWORD DETECTION
        features['sql_keywords'] = sum(1 for kw in self.sql_keywords if kw in decoded_lower)
        features['xss_keywords'] = sum(1 for kw in self.xss_keywords if kw in decoded_lower)
        features['cmd_keywords'] = sum(1 for kw in self.command_keywords if kw in decoded_lower)
        features['traversal_patterns'] = sum(1 for pattern in self.traversal_patterns if pattern in decoded_lower or pattern in url_lower)
        
        # 5. PATTERN DETECTION
        features['suspicious_patterns'] = sum(1 for pattern in self.suspicious_patterns if pattern in decoded_lower or pattern in url_lower)
        
        # 6. Encoding detection
        features['suspicious_encodings'] = sum(1 for enc in self.suspicious_encodings if enc in url_lower)
        features['double_encoding'] = 1 if '%25' in url_lower else 0  # %25 = encoded %
        
        # 7. Operators
        features['sql_operators'] = decoded.count("'") + decoded.count('"') + decoded.count('--') + decoded.count('/*')
        features['command_operators'] = decoded.count('|') + decoded.count(';') + decoded.count('&') + decoded.count('`')
        features['html_tags'] = decoded.count('<') + decoded.count('>')
        
        # 8. Specific attack indicators
        features['has_quotes'] = 1 if ("'" in decoded or '"' in decoded) else 0
        features['has_union'] = 1 if 'union' in decoded_lower else 0
        features['has_select'] = 1 if 'select' in decoded_lower else 0
        features['has_script'] = 1 if 'script' in decoded_lower else 0
        features['has_dots'] = url.count('..')
        features['has_null_byte'] = 1 if '%00' in url_lower or '\\0' in decoded_lower else 0
        
        # 9. Advanced patterns
        features['repeated_chars'] = max([len(list(g)) for k, g in __import__('itertools').groupby(url)], default=0)
        features['consecutive_specials'] = self._count_consecutive_specials(decoded)
        
        # 10. N-gram anomaly (NEW!)
        features['ngram_anomaly'] = self.calculate_ngram_anomaly_score(decoded_lower)
        
        # 11. Structural features (NEW!)
        features['slash_count'] = url.count('/')
        features['equals_count'] = url.count('=')
        features['ampersand_count'] = url.count('&')
        features['question_count'] = url.count('?')
        
        # 12. Numeric/Alpha ratio
        alpha_count = sum(1 for c in decoded if c.isalpha())
        num_count = sum(1 for c in decoded if c.isdigit())
        features['alpha_ratio'] = alpha_count / max(len(decoded), 1)
        features['numeric_ratio'] = num_count / max(len(decoded), 1)
        
        # 13. Case variation (potential obfuscation)
        upper_count = sum(1 for c in decoded if c.isupper())
        features['case_variation'] = upper_count / max(alpha_count, 1) if alpha_count > 0 else 0
        
        # 14. Hexadecimal detection
        features['hex_sequences'] = len(re.findall(r'\\x[0-9a-fA-F]{2}', decoded))
        
        # 15. Base64-like patterns
        features['base64_like'] = 1 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', decoded) else 0
        
        return features
    
    def _count_consecutive_specials(self, string):
        """Count maximum consecutive special characters"""
        count = 0
        max_count = 0
        for char in string:
            if not char.isalnum():
                count += 1
                max_count = max(max_count, count)
            else:
                count = 0
        return max_count
    
    def train_baseline(self, normal_requests):
        """Train on normal traffic with ML and statistical analysis"""
        print(f"\n[Enhanced Detector] Training on {len(normal_requests)} normal requests...")
        
        if not normal_requests:
            return
        
        # Extract features from all normal requests
        all_features = [self.extract_features(req) for req in normal_requests]
        feature_names = list(all_features[0].keys())
        
        # Build feature matrix for ML
        feature_matrix = []
        for features in all_features:
            feature_matrix.append([features[name] for name in feature_names])
        feature_matrix = np.array(feature_matrix)
        
        # Calculate statistical baselines
        self.baseline_stats = {}
        self.feature_distributions = {}
        
        for i, name in enumerate(feature_names):
            values = feature_matrix[:, i]
            self.baseline_stats[f'avg_{name}'] = np.mean(values)
            self.feature_distributions[name] = {
                'mean': np.mean(values),
                'std': np.std(values) + 1e-6,  # Add small epsilon to avoid division by zero
                'min': np.min(values),
                'max': np.max(values),
                'median': np.median(values),
                'q75': np.percentile(values, 75),
                'q95': np.percentile(values, 95),
            }
        
        # Build parameter whitelist
        for req in normal_requests:
            url = req.get('payload', '')
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                self.param_whitelist.update(params.keys())
            except:
                pass
        
        # Build n-gram models
        print("[Enhanced Detector] Building n-gram models...")
        for req in normal_requests:
            url = req.get('payload', '') + req.get('path', '')
            decoded = unquote(url).lower()
            self.normal_bigrams.update(self.extract_ngrams(decoded, 2))
            self.normal_trigrams.update(self.extract_ngrams(decoded, 3))
        
        # Build endpoint-specific thresholds
        print("[Enhanced Detector] Calculating endpoint thresholds...")
        endpoint_scores = defaultdict(list)
        for req in normal_requests:
            path = req.get('path', '/')
            features = self.extract_features(req)
            score, _ = self.calculate_anomaly_score(features, use_adaptive=False)
            endpoint_scores[path].append(score)
        
        for path, scores in endpoint_scores.items():
            # Set threshold at 95th percentile of normal scores + buffer
            if scores:
                self.endpoint_thresholds[path] = np.percentile(scores, 95) + 20
        
        # Train ML model if available
        if self.enable_ml:
            print("[Enhanced Detector] Training Isolation Forest...")
            try:
                self.scaler = StandardScaler()
                scaled_features = self.scaler.fit_transform(feature_matrix)
                
                self.isolation_forest = IsolationForest(
                    contamination=0.01,  # Assume 1% contamination in training data
                    random_state=42,
                    n_estimators=100,
                    max_samples='auto'
                )
                self.isolation_forest.fit(scaled_features)
                
                print("[Enhanced Detector] ✅ ML model trained successfully")
            except Exception as e:
                print(f"[Enhanced Detector] ⚠️  ML training failed: {e}")
                self.enable_ml = False
        
        self.trained = True
        print(f"[Enhanced Detector] ✅ Training complete")
        print(f"  - Feature distributions: {len(self.feature_distributions)}")
        print(f"  - Parameter whitelist: {len(self.param_whitelist)} params")
        print(f"  - Bigrams: {len(self.normal_bigrams)}, Trigrams: {len(self.normal_trigrams)}")
        print(f"  - Endpoint thresholds: {len(self.endpoint_thresholds)} paths")
        if self.enable_ml:
            print(f"  - ML: Isolation Forest with {self.isolation_forest.n_estimators} trees")
    
    def calculate_statistical_anomaly_score(self, features):
        """Calculate z-score based anomaly detection"""
        if not self.feature_distributions:
            return 0, {}
        
        z_scores = {}
        significant_anomalies = []
        
        for feature_name, value in features.items():
            if feature_name in self.feature_distributions:
                dist = self.feature_distributions[feature_name]
                z_score = abs((value - dist['mean']) / dist['std'])
                z_scores[feature_name] = z_score
                
                # Flag significant anomalies (z-score > 3)
                if z_score > 3:
                    significant_anomalies.append((feature_name, z_score))
        
        # Calculate total score from significant anomalies
        stat_score = sum(min(z * 10, 50) for _, z in significant_anomalies)  # Cap individual contribution
        
        breakdown = {}
        for feature_name, z_score in sorted(significant_anomalies, key=lambda x: -x[1])[:5]:
            breakdown[f"Z-score {feature_name}"] = f"+{min(z_score * 10, 50):.0f}"
        
        return stat_score, breakdown
    
    def calculate_ml_anomaly_score(self, features):
        """Calculate ML-based anomaly score"""
        if not self.enable_ml or not self.isolation_forest:
            return 0
        
        try:
            feature_names = list(self.feature_distributions.keys())
            feature_vector = np.array([[features[name] for name in feature_names]])
            scaled_vector = self.scaler.transform(feature_vector)
            
            # Get anomaly score (lower is more anomalous)
            # Returns values around -1 to 1, where negative is anomalous
            ml_score = -self.isolation_forest.score_samples(scaled_vector)[0]
            
            # Convert to 0-100 scale (0 = normal, 100 = highly anomalous)
            normalized_score = max(0, ml_score * 100)
            
            return min(normalized_score, 100)  # Cap at 100
        except Exception as e:
            return 0
    
    def calculate_anomaly_score(self, features, use_adaptive=True):
        """Calculate weighted anomaly score with ensemble approach"""
        if not self.trained:
            return 0, {}
        
        total_score = 0
        breakdown = {}
        
        # ===========================
        # METHOD 1: RULE-BASED SCORING
        # ===========================
        rule_score = 0
        
        # CRITICAL KEYWORDS (very high weight!)
        if features['sql_keywords'] > self.baseline_stats.get('avg_sql_keywords', 0):
            sql_score = (features['sql_keywords'] - self.baseline_stats['avg_sql_keywords']) * 45
            rule_score += sql_score
            breakdown['SQL keywords'] = f"+{sql_score:.0f}"
        
        if features['xss_keywords'] > self.baseline_stats.get('avg_xss_keywords', 0):
            xss_score = (features['xss_keywords'] - self.baseline_stats['avg_xss_keywords']) * 45
            rule_score += xss_score
            breakdown['XSS keywords'] = f"+{xss_score:.0f}"
        
        if features['cmd_keywords'] > self.baseline_stats.get('avg_cmd_keywords', 0):
            cmd_score = (features['cmd_keywords'] - self.baseline_stats['avg_cmd_keywords']) * 50
            rule_score += cmd_score
            breakdown['CMD keywords'] = f"+{cmd_score:.0f}"
        
        if features['traversal_patterns'] > self.baseline_stats.get('avg_traversal_patterns', 0):
            trav_score = (features['traversal_patterns'] - self.baseline_stats['avg_traversal_patterns']) * 55
            rule_score += trav_score
            breakdown['Path traversal'] = f"+{trav_score:.0f}"
        
        # SUSPICIOUS PATTERNS
        if features['suspicious_patterns'] > self.baseline_stats.get('avg_suspicious_patterns', 0):
            pattern_score = (features['suspicious_patterns'] - self.baseline_stats['avg_suspicious_patterns']) * 30
            rule_score += pattern_score
            breakdown['Suspicious patterns'] = f"+{pattern_score:.0f}"
        
        # SUSPICIOUS ENCODINGS
        if features['suspicious_encodings'] > self.baseline_stats.get('avg_suspicious_encodings', 0):
            enc_score = (features['suspicious_encodings'] - self.baseline_stats['avg_suspicious_encodings']) * 25
            rule_score += enc_score
            breakdown['Suspicious encodings'] = f"+{enc_score:.0f}"
        
        # OPERATORS
        if features['sql_operators'] > 2:
            sql_op_score = features['sql_operators'] * 18
            rule_score += sql_op_score
            breakdown['SQL operators'] = f"+{sql_op_score:.0f}"
        
        if features['command_operators'] > 1:
            cmd_op_score = features['command_operators'] * 25
            rule_score += cmd_op_score
            breakdown['Command operators'] = f"+{cmd_op_score:.0f}"
        
        if features['html_tags'] > 0:
            html_score = features['html_tags'] * 18
            rule_score += html_score
            breakdown['HTML tags'] = f"+{html_score:.0f}"
        
        # SPECIFIC INDICATORS
        if features['has_quotes']:
            rule_score += 12
            breakdown['Has quotes'] = "+12"
        
        if features['has_union'] or features['has_select']:
            rule_score += 30
            breakdown['SQL injection indicators'] = "+30"
        
        if features['has_script']:
            rule_score += 30
            breakdown['XSS indicators'] = "+30"
        
        if features['has_dots'] > 1:
            dots_score = features['has_dots'] * 20
            rule_score += dots_score
            breakdown['Directory dots'] = f"+{dots_score:.0f}"
        
        if features['has_null_byte']:
            rule_score += 35
            breakdown['Null byte'] = "+35"
        
        # SUSPICIOUS CHARACTERS
        if features['suspicious_char_count'] > 3:
            char_score = features['suspicious_char_count'] * 10
            rule_score += char_score
            breakdown['Suspicious chars'] = f"+{char_score:.0f}"
        
        # HIGH ENTROPY
        entropy_diff = features['entropy'] - self.baseline_stats.get('avg_entropy', 4.0)
        if entropy_diff > 1.0:
            entropy_score = entropy_diff * 10
            rule_score += entropy_score
            breakdown['High entropy'] = f"+{entropy_score:.0f}"
        
        # LONG REQUEST
        avg_length = self.baseline_stats.get('avg_length', 50)
        length_ratio = features['length'] / max(avg_length, 1)
        if length_ratio > 2.5:
            length_score = (length_ratio - 2.5) * 18
            rule_score += length_score
            breakdown['Unusual length'] = f"+{length_score:.0f}"
        
        # N-GRAM ANOMALY (NEW!)
        if features.get('ngram_anomaly', 0) > 15:
            rule_score += features['ngram_anomaly']
            breakdown['N-gram anomaly'] = f"+{features['ngram_anomaly']:.0f}"
        
        # UNKNOWN PARAMETERS (NEW!)
        if features.get('unknown_params', 0) > 0:
            param_score = features['unknown_params'] * 15
            rule_score += param_score
            breakdown['Unknown params'] = f"+{param_score:.0f}"
        
        # DOUBLE ENCODING (NEW!)
        if features.get('double_encoding', 0):
            rule_score += 25
            breakdown['Double encoding'] = "+25"
        
        # REPEATED/CONSECUTIVE SPECIALS
        if features['repeated_chars'] > 5:
            rule_score += features['repeated_chars'] * 4
        
        if features['consecutive_specials'] > 3:
            consec_score = features['consecutive_specials'] * 6
            rule_score += consec_score
            breakdown['Consecutive specials'] = f"+{consec_score:.0f}"
        
        # HEX SEQUENCES
        if features.get('hex_sequences', 0) > 2:
            hex_score = features['hex_sequences'] * 12
            rule_score += hex_score
            breakdown['Hex sequences'] = f"+{hex_score:.0f}"
        
        # BASE64-LIKE
        if features.get('base64_like', 0):
            rule_score += 20
            breakdown['Base64-like pattern'] = "+20"
        
        total_score += rule_score * 0.5  # 50% weight
        
        # ===========================
        # METHOD 2: STATISTICAL SCORING
        # ===========================
        stat_score, stat_breakdown = self.calculate_statistical_anomaly_score(features)
        total_score += stat_score * 0.3  # 30% weight
        breakdown.update({f"Stat-{k}": v for k, v in stat_breakdown.items()})
        
        # ===========================
        # METHOD 3: ML SCORING
        # ===========================
        if self.enable_ml:
            ml_score = self.calculate_ml_anomaly_score(features)
            total_score += ml_score * 0.2  # 20% weight
            if ml_score > 10:
                breakdown['ML anomaly'] = f"+{ml_score:.0f}"
        
        return total_score, breakdown
    
    def get_adaptive_threshold(self, request_data, default=25):
        """Get adaptive threshold based on request context"""
        if not self.trained:
            return default
        
        path = request_data.get('path', '/')
        
        # Use endpoint-specific threshold if available
        if path in self.endpoint_thresholds:
            return self.endpoint_thresholds[path]
        
        # Use default
        return default
    
    def is_anomalous(self, request_data, threshold=None):
        """Detect if request is anomalous with adaptive thresholding"""
        features = self.extract_features(request_data)
        score, breakdown = self.calculate_anomaly_score(features)
        
        # Use adaptive threshold if not specified
        if threshold is None:
            threshold = self.get_adaptive_threshold(request_data, default=25)
        
        is_anomalous = score >= threshold
        
        details = {
            'score': score,
            'threshold': threshold,
            'breakdown': breakdown,
            'top_features': {
                'sql_keywords': features['sql_keywords'],
                'xss_keywords': features['xss_keywords'],
                'cmd_keywords': features['cmd_keywords'],
                'traversal_patterns': features['traversal_patterns'],
                'suspicious_patterns': features['suspicious_patterns'],
                'suspicious_encodings': features['suspicious_encodings'],
                'ngram_anomaly': features.get('ngram_anomaly', 0),
            },
            'ml_enabled': self.enable_ml,
        }
        
        return is_anomalous, score, details
    
    def save_model(self, filepath='anomaly_detector_model.pkl'):
        """Save trained model to file"""
        if not self.trained:
            print("⚠️  Model not trained yet")
            return False
        
        model_data = {
            'baseline_stats': self.baseline_stats,
            'feature_distributions': self.feature_distributions,
            'endpoint_thresholds': dict(self.endpoint_thresholds),
            'param_whitelist': self.param_whitelist,
            'normal_bigrams': self.normal_bigrams,
            'normal_trigrams': self.normal_trigrams,
            'scaler': self.scaler,
            'isolation_forest': self.isolation_forest,
        }
        
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
            print(f"✅ Model saved to {filepath}")
            return True
        except Exception as e:
            print(f"❌ Error saving model: {e}")
            return False
    
    def load_model(self, filepath='anomaly_detector_model.pkl'):
        """Load trained model from file"""
        if not os.path.exists(filepath):
            print(f"⚠️  Model file not found: {filepath}")
            return False
        
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.baseline_stats = model_data['baseline_stats']
            self.feature_distributions = model_data['feature_distributions']
            self.endpoint_thresholds = defaultdict(lambda: 25, model_data['endpoint_thresholds'])
            self.param_whitelist = model_data['param_whitelist']
            self.normal_bigrams = model_data['normal_bigrams']
            self.normal_trigrams = model_data['normal_trigrams']
            self.scaler = model_data['scaler']
            self.isolation_forest = model_data['isolation_forest']
            
            self.trained = True
            self.enable_ml = self.isolation_forest is not None
            
            print(f"✅ Model loaded from {filepath}")
            return True
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return False


# Backward compatibility
UltraAnomalyDetector = EnhancedUltraAnomalyDetector
AnomalyDetector = EnhancedUltraAnomalyDetector


if __name__ == '__main__':
    print("="*70)
    print("ENHANCED ULTRA-AGGRESSIVE ANOMALY DETECTOR")
    print("="*70)
    print()
    print("Multi-layered detection system:")
    print("  1. Rule-based scoring (50% weight)")
    print("  2. Statistical z-score analysis (30% weight)")
    print("  3. ML Isolation Forest (20% weight)")
    print()
    print("Key improvements:")
    print("  ✅ Machine Learning layer with Isolation Forest")
    print("  ✅ Statistical anomaly detection (z-scores)")
    print("  ✅ Adaptive thresholds per endpoint")
    print("  ✅ N-gram analysis for obfuscation detection")
    print("  ✅ Context-aware scoring")
    print("  ✅ Improved false positive reduction")
    print("  ✅ Feature normalization and scaling")
    print("  ✅ Model persistence (save/load)")
    print()
    print("Target performance:")
    print("  🎯 Detection rate: 85-95%")
    print("  🎯 False positive rate: <5%")
    print()
    
    if not ML_AVAILABLE:
        print("⚠️  WARNING: scikit-learn not installed")
        print("   Install with: pip install scikit-learn numpy")
        print("   ML features will be disabled")
    else:
        print("✅ All dependencies available")