from ultra_anomaly_detection import AnomalyDetector
import time

def test_accuracy():
    detector = AnomalyDetector()
    
    # Normal traffic samples
    normal_samples = [
        {'ip': '192.168.1.10', 'path': '/login', 'payload': 'username=john&password=pass123', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/dashboard', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.12', 'path': '/profile', 'payload': 'name=Alice&email=alice@example.com', 'timestamp': time.time()},
        # Add 20+ more normal samples...
    ]
    
    # Malicious samples
    malicious_samples = [
        {'ip': '10.0.0.5', 'path': '/search', 'payload': "' OR '1'='1' --", 'timestamp': time.time()},
        {'ip': '10.0.0.5', 'path': '/search', 'payload': '<script>alert(1)</script>', 'timestamp': time.time()},
        {'ip': '10.0.0.6', 'path': '/cmd', 'payload': '; cat /etc/passwd', 'timestamp': time.time()},
        # Add 20+ more attack samples...
    ]
    
    # Train on normal data
    detector.train_baseline(normal_samples)
    
    # Test detection
    true_positives = 0  # Correctly identified attacks
    false_positives = 0  # Normal flagged as attack
    true_negatives = 0  # Correctly identified normal
    false_negatives = 0  # Missed attacks
    
    print("Testing normal traffic...")
    for sample in normal_samples:
        is_anom, score, _ = detector.is_anomalous(sample)
        if is_anom:
            false_positives += 1
        else:
            true_negatives += 1
    
    print("Testing malicious traffic...")
    for sample in malicious_samples:
        is_anom, score, _ = detector.is_anomalous(sample)
        if is_anom:
            true_positives += 1
        else:
            false_negatives += 1
    
    # Calculate metrics
    total = true_positives + false_positives + true_negatives + false_negatives
    accuracy = (true_positives + true_negatives) / total * 100
    precision = true_positives / (true_positives + false_positives) * 100 if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) * 100 if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    print("\n" + "="*60)
    print("ANOMALY DETECTION ACCURACY RESULTS")
    print("="*60)
    print(f"True Positives:  {true_positives}")
    print(f"False Positives: {false_positives}")
    print(f"True Negatives:  {true_negatives}")
    print(f"False Negatives: {false_negatives}")
    print("-"*60)
    print(f"Accuracy:  {accuracy:.2f}%")
    print(f"Precision: {precision:.2f}%")
    print(f"Recall:    {recall:.2f}%")
    print(f"F1-Score:  {f1_score:.2f}%")
    print("="*60)
    
    if accuracy >= 80:
        print("✅ OBJECTIVE 3 MET: Accuracy >= 80%")
    else:
        print("⚠️  OBJECTIVE 3 NOT MET: Accuracy < 80%")
        print("   Consider tuning thresholds or adding more features")

if __name__ == '__main__':
    test_accuracy()