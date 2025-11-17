#!/usr/bin/env python3
"""
Analyze Missed Attacks
Identifies patterns in attacks that aren't being detected
"""

import sys
sys.path.insert(0, '/mnt/user-data/outputs')

from ultra_anomaly_detection import UltraAnomalyDetector
import csv
from urllib.parse import unquote

def analyze_missed_attacks(csv_file='datasets/csic2010/CSIC_2010.csv'):
    """Analyze which attacks are being missed"""
    
    print("="*70)
    print("ANALYZING MISSED ATTACKS")
    print("="*70)
    print()
    
    # Load detector
    detector = UltraAnomalyDetector()
    
    # Load normal traffic for training
    print("Loading dataset...")
    normal_samples = []
    attack_samples = []
    
    with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        
        for row in reader:
            if len(row) < 3:
                continue
            
            classification = row[0].strip()
            url = row[-1].strip() if row else ''
            
            sample = {'path': '', 'payload': url, 'ip': '127.0.0.1', 'timestamp': 0}
            
            if classification == 'Normal':
                normal_samples.append(sample)
            elif classification == 'Anomalous':
                attack_samples.append(sample)
    
    print(f"Loaded {len(normal_samples)} normal, {len(attack_samples)} attacks")
    
    # Train detector
    print("\nTraining detector...")
    detector.train_baseline(normal_samples[:2000])
    
    # Test on attacks
    print("\nTesting on attacks...")
    missed = []
    detected = []
    
    for i, attack in enumerate(attack_samples[:500], 1):
        is_anom, score, details = detector.is_anomalous(attack, threshold=30)
        
        if is_anom:
            detected.append((attack, score, details))
        else:
            missed.append((attack, score, details))
    
    print(f"\nResults:")
    print(f"  Detected: {len(detected)} ({len(detected)/5:.1f}%)")
    print(f"  Missed:   {len(missed)} ({len(missed)/5:.1f}%)")
    
    # Analyze missed attacks
    print("\n" + "="*70)
    print("ANALYZING MISSED ATTACKS")
    print("="*70)
    
    # Sample missed attacks
    print("\nSample of missed attacks (showing first 20):")
    for i, (attack, score, details) in enumerate(missed[:20], 1):
        url = attack['payload'][:100]
        decoded = unquote(url)[:100]
        
        print(f"\n#{i} Score: {score:.0f}")
        print(f"  URL: {url}")
        if decoded != url:
            print(f"  Decoded: {decoded}")
        
        # Show what features were found
        if details['top_features']:
            feats = details['top_features']
            if any(feats.values()):
                print(f"  Features: SQL={feats['sql_keywords']}, XSS={feats['xss_keywords']}, "
                      f"CMD={feats['cmd_keywords']}, TRAV={feats['traversal_patterns']}")
    
    # Pattern analysis
    print("\n" + "="*70)
    print("PATTERN ANALYSIS OF MISSED ATTACKS")
    print("="*70)
    
    # Check common patterns in missed attacks
    patterns = {
        'has_quotes': 0,
        'has_equals': 0,
        'has_script': 0,
        'has_union': 0,
        'has_select': 0,
        'has_slash': 0,
        'has_percent': 0,
        'has_ampersand': 0,
        'very_short': 0,
        'very_long': 0,
    }
    
    for attack, score, details in missed:
        url = attack['payload'].lower()
        decoded = unquote(url).lower()
        
        if "'" in url or '"' in url:
            patterns['has_quotes'] += 1
        if '=' in url:
            patterns['has_equals'] += 1
        if 'script' in decoded:
            patterns['has_script'] += 1
        if 'union' in decoded:
            patterns['has_union'] += 1
        if 'select' in decoded:
            patterns['has_select'] += 1
        if '/' in url and url.count('/') > 3:
            patterns['has_slash'] += 1
        if '%' in url:
            patterns['has_percent'] += 1
        if '&' in url:
            patterns['has_ampersand'] += 1
        if len(url) < 50:
            patterns['very_short'] += 1
        if len(url) > 200:
            patterns['very_long'] += 1
    
    print("\nCommon patterns in missed attacks:")
    total_missed = len(missed)
    for pattern, count in sorted(patterns.items(), key=lambda x: -x[1]):
        pct = (count / total_missed * 100) if total_missed > 0 else 0
        print(f"  {pattern:20s}: {count:3d} ({pct:5.1f}%)")
    
    # Score distribution
    print("\n" + "="*70)
    print("SCORE DISTRIBUTION")
    print("="*70)
    
    score_buckets = {
        '0-10': 0,
        '11-20': 0,
        '21-30': 0,
        '31-40': 0,
        '41-50': 0,
        '51+': 0
    }
    
    for attack, score, details in missed:
        if score <= 10:
            score_buckets['0-10'] += 1
        elif score <= 20:
            score_buckets['11-20'] += 1
        elif score <= 30:
            score_buckets['21-30'] += 1
        elif score <= 40:
            score_buckets['31-40'] += 1
        elif score <= 50:
            score_buckets['41-50'] += 1
        else:
            score_buckets['51+'] += 1
    
    print("\nScore distribution of MISSED attacks:")
    for bucket, count in score_buckets.items():
        pct = (count / total_missed * 100) if total_missed > 0 else 0
        bar = '█' * int(pct / 2)
        print(f"  {bucket:10s}: {count:3d} ({pct:5.1f}%) {bar}")
    
    print("\n" + "="*70)
    print("RECOMMENDATIONS")
    print("="*70)
    
    # Provide recommendations
    if score_buckets['21-30'] > total_missed * 0.3:
        print("\n1. ⭐ LOWER THRESHOLD to 20 or 25")
        print("   Many attacks score 21-30 (just below threshold)")
    
    if patterns['has_percent'] > total_missed * 0.5:
        print("\n2. ⭐ INCREASE encoding detection weight")
        print("   Many missed attacks use URL encoding")
    
    if patterns['has_equals'] > total_missed * 0.7:
        print("\n3. ⭐ ADD suspicious parameter patterns")
        print("   Many attacks have suspicious = usage")
    
    if patterns['has_quotes'] > total_missed * 0.4:
        print("\n4. ⭐ INCREASE quote detection weight")
        print("   Many attacks contain quotes")
    
    print("\n" + "="*70)
    
    return missed, detected


if __name__ == '__main__':
    import os
    
    csv_file = 'datasets/csic2010/CSIC_2010.csv'
    
    if not os.path.exists(csv_file):
        print(f"❌ Error: {csv_file} not found")
        print("Please run this from your project directory")
        input("\nPress Enter to exit...")
    else:
        try:
            missed, detected = analyze_missed_attacks(csv_file)
            print("\n✅ Analysis complete!")
            input("\nPress Enter to exit...")
        except Exception as e:
            print(f"\n❌ Error: {e}")
            import traceback
            traceback.print_exc()
            input("\nPress Enter to exit...")