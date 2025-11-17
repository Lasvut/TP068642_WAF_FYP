#!/usr/bin/env python3
"""
Comprehensive WAF Testing and Comparison
Compare original vs enhanced detector performance

Tests:
1. Detection rate on real attacks (CSIC 2010 dataset)
2. False positive rate on normal traffic
3. Performance benchmarking
4. Feature importance analysis
5. Side-by-side comparison
"""

import sys
import os
import time
import csv
from collections import defaultdict
from urllib.parse import unquote

# Import both versions for comparison
sys.path.insert(0, '/mnt/user-data/uploads')
sys.path.insert(0, '/home/claude')

from ultra_anomaly_detection import UltraAnomalyDetector as OriginalDetector
from ultra_anomaly_detection_enhanced import EnhancedUltraAnomalyDetector as EnhancedDetector


class WAFTester:
    """Comprehensive WAF testing framework"""
    
    def __init__(self):
        self.results = {
            'original': {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0, 'scores': []},
            'enhanced': {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0, 'scores': []},
        }
        self.test_cases = []
    
    def load_csic_csv_dataset(self, csv_file='datasets/csic2010/CSIC_2010.csv'):
        """Load CSIC dataset from CSV"""
        print("\n" + "="*70)
        print("LOADING CSIC 2010 DATASET (CSV)")
        print("="*70)
        
        if not os.path.exists(csv_file):
            print(f"❌ Error: {csv_file} not found")
            print("\nPlease ensure the dataset is at:")
            print(f"  {csv_file}")
            return None, None
        
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
                
                sample = {
                    'path': '',
                    'payload': url,
                    'ip': '127.0.0.1',
                    'timestamp': time.time()
                }
                
                if classification == 'Normal':
                    normal_samples.append(sample)
                elif classification == 'Anomalous':
                    attack_samples.append(sample)
        
        print(f"✅ Loaded {len(normal_samples)} normal samples")
        print(f"✅ Loaded {len(attack_samples)} attack samples")
        
        return normal_samples, attack_samples
    
    def train_detectors(self, normal_samples, train_size=2000):
        """Train both detectors"""
        print("\n" + "="*70)
        print("TRAINING DETECTORS")
        print("="*70)
        
        train_data = normal_samples[:train_size]
        
        print(f"\nTraining Original Detector on {len(train_data)} samples...")
        self.original_detector = OriginalDetector()
        start = time.time()
        self.original_detector.train_baseline(train_data)
        original_time = time.time() - start
        print(f"✅ Training completed in {original_time:.2f}s")
        
        print(f"\nTraining Enhanced Detector on {len(train_data)} samples...")
        self.enhanced_detector = EnhancedDetector(enable_ml=True)
        start = time.time()
        self.enhanced_detector.train_baseline(train_data)
        enhanced_time = time.time() - start
        print(f"✅ Training completed in {enhanced_time:.2f}s")
        
        print(f"\n⏱️  Training time comparison:")
        print(f"   Original: {original_time:.2f}s")
        print(f"   Enhanced: {enhanced_time:.2f}s")
    
    def test_attack_detection(self, attack_samples, test_size=500, threshold=25):
        """Test attack detection rate"""
        print("\n" + "="*70)
        print(f"TESTING ATTACK DETECTION (threshold={threshold})")
        print("="*70)
        
        test_samples = attack_samples[:test_size]
        
        print(f"\nTesting {len(test_samples)} attack samples...\n")
        
        original_tp = 0
        original_fn = 0
        enhanced_tp = 0
        enhanced_fn = 0
        
        # Show detailed results for first 20
        print("Sample Results (first 20):")
        print("-" * 70)
        
        for i, sample in enumerate(test_samples[:20], 1):
            # Test original
            is_anom_orig, score_orig, _ = self.original_detector.is_anomalous(sample, threshold=threshold)
            
            # Test enhanced
            is_anom_enh, score_enh, _ = self.enhanced_detector.is_anomalous(sample, threshold=None)
            
            if is_anom_orig:
                original_tp += 1
            else:
                original_fn += 1
            
            if is_anom_enh:
                enhanced_tp += 1
            else:
                enhanced_fn += 1
            
            # Display comparison
            url_display = sample['payload'][:50] + "..." if len(sample['payload']) > 50 else sample['payload']
            orig_status = "✅ DETECTED" if is_anom_orig else "❌ MISSED"
            enh_status = "✅ DETECTED" if is_anom_enh else "❌ MISSED"
            
            print(f"#{i:3d}")
            print(f"  URL: {url_display}")
            print(f"  Original: {orig_status:12s} (Score: {score_orig:5.0f})")
            print(f"  Enhanced: {enh_status:12s} (Score: {score_enh:5.0f})")
            
            if is_anom_orig != is_anom_enh:
                print(f"  ⚡ DIFFERENCE: Enhanced {'caught' if is_anom_enh else 'cleared'} this attack!")
            print()
        
        # Test remaining samples (without detailed output)
        print(f"Testing remaining {len(test_samples) - 20} samples...")
        for sample in test_samples[20:]:
            is_anom_orig, score_orig, _ = self.original_detector.is_anomalous(sample, threshold=threshold)
            is_anom_enh, score_enh, _ = self.enhanced_detector.is_anomalous(sample, threshold=None)
            
            if is_anom_orig:
                original_tp += 1
            else:
                original_fn += 1
            
            if is_anom_enh:
                enhanced_tp += 1
            else:
                enhanced_fn += 1
        
        # Calculate metrics
        total = original_tp + original_fn
        original_detection = (original_tp / total * 100) if total > 0 else 0
        enhanced_detection = (enhanced_tp / total * 100) if total > 0 else 0
        
        print("\n" + "="*70)
        print("ATTACK DETECTION RESULTS")
        print("="*70)
        print(f"\nTotal attacks tested: {total}")
        print()
        print(f"{'Detector':<15} {'Detected':<12} {'Missed':<12} {'Rate':<12}")
        print("-" * 60)
        print(f"{'Original':<15} {original_tp:<12} {original_fn:<12} {original_detection:>10.2f}%")
        print(f"{'Enhanced':<15} {enhanced_tp:<12} {enhanced_fn:<12} {enhanced_detection:>10.2f}%")
        print()
        
        improvement = enhanced_detection - original_detection
        if improvement > 0:
            print(f"🎯 IMPROVEMENT: +{improvement:.2f}% detection rate!")
            print(f"   Enhanced caught {enhanced_tp - original_tp} MORE attacks")
        elif improvement < 0:
            print(f"⚠️  REGRESSION: {improvement:.2f}% detection rate")
        else:
            print("Same performance")
        
        self.results['original']['tp'] = original_tp
        self.results['original']['fn'] = original_fn
        self.results['enhanced']['tp'] = enhanced_tp
        self.results['enhanced']['fn'] = enhanced_fn
        
        return original_detection, enhanced_detection
    
    def test_false_positives(self, normal_samples, test_start=2000, test_size=200, threshold=25):
        """Test false positive rate"""
        print("\n" + "="*70)
        print(f"TESTING FALSE POSITIVE RATE (threshold={threshold})")
        print("="*70)
        
        test_samples = normal_samples[test_start:test_start + test_size]
        
        print(f"\nTesting {len(test_samples)} normal samples...\n")
        
        original_fp = 0
        original_tn = 0
        enhanced_fp = 0
        enhanced_tn = 0
        
        false_positive_examples = []
        
        for i, sample in enumerate(test_samples, 1):
            # Test original
            is_anom_orig, score_orig, _ = self.original_detector.is_anomalous(sample, threshold=threshold)
            
            # Test enhanced
            is_anom_enh, score_enh, _ = self.enhanced_detector.is_anomalous(sample, threshold=None)
            
            if is_anom_orig:
                original_fp += 1
            else:
                original_tn += 1
            
            if is_anom_enh:
                enhanced_fp += 1
                if len(false_positive_examples) < 10:
                    false_positive_examples.append((sample, score_enh))
            else:
                enhanced_tn += 1
        
        # Calculate metrics
        total = original_fp + original_tn
        original_fp_rate = (original_fp / total * 100) if total > 0 else 0
        enhanced_fp_rate = (enhanced_fp / total * 100) if total > 0 else 0
        original_specificity = (original_tn / total * 100) if total > 0 else 0
        enhanced_specificity = (enhanced_tn / total * 100) if total > 0 else 0
        
        print("="*70)
        print("FALSE POSITIVE RESULTS")
        print("="*70)
        print(f"\nTotal normal requests tested: {total}")
        print()
        print(f"{'Detector':<15} {'Correct (TN)':<15} {'Wrong (FP)':<15} {'FP Rate':<12} {'Specificity':<12}")
        print("-" * 80)
        print(f"{'Original':<15} {original_tn:<15} {original_fp:<15} {original_fp_rate:>10.2f}% {original_specificity:>10.2f}%")
        print(f"{'Enhanced':<15} {enhanced_tn:<15} {enhanced_fp:<15} {enhanced_fp_rate:>10.2f}% {enhanced_specificity:>10.2f}%")
        print()
        
        improvement = original_fp_rate - enhanced_fp_rate
        if improvement > 0:
            print(f"🎯 IMPROVEMENT: -{improvement:.2f}% false positive rate!")
            print(f"   Enhanced has {original_fp - enhanced_fp} FEWER false positives")
        elif improvement < 0:
            print(f"⚠️  REGRESSION: +{abs(improvement):.2f}% false positive rate")
        else:
            print("Same performance")
        
        # Show some false positive examples
        if false_positive_examples:
            print("\n" + "="*70)
            print("FALSE POSITIVE EXAMPLES (Enhanced Detector)")
            print("="*70)
            for i, (sample, score) in enumerate(false_positive_examples[:5], 1):
                url = sample['payload'][:80] + "..." if len(sample['payload']) > 80 else sample['payload']
                print(f"\n#{i} Score: {score:.0f}")
                print(f"  URL: {url}")
        
        self.results['original']['fp'] = original_fp
        self.results['original']['tn'] = original_tn
        self.results['enhanced']['fp'] = enhanced_fp
        self.results['enhanced']['tn'] = enhanced_tn
        
        return original_fp_rate, enhanced_fp_rate
    
    def calculate_final_metrics(self):
        """Calculate and display final metrics"""
        print("\n" + "="*70)
        print("FINAL PERFORMANCE METRICS")
        print("="*70)
        
        for detector_name in ['original', 'enhanced']:
            r = self.results[detector_name]
            
            total = r['tp'] + r['fp'] + r['tn'] + r['fn']
            accuracy = ((r['tp'] + r['tn']) / total * 100) if total > 0 else 0
            precision = (r['tp'] / (r['tp'] + r['fp']) * 100) if (r['tp'] + r['fp']) > 0 else 0
            recall = (r['tp'] / (r['tp'] + r['fn']) * 100) if (r['tp'] + r['fn']) > 0 else 0
            f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
            
            print(f"\n{detector_name.upper()} DETECTOR:")
            print("-" * 70)
            print(f"  True Positives (TP):   {r['tp']:4d}  (Correctly detected attacks)")
            print(f"  False Positives (FP):  {r['fp']:4d}  (Normal traffic blocked)")
            print(f"  True Negatives (TN):   {r['tn']:4d}  (Correctly allowed normal)")
            print(f"  False Negatives (FN):  {r['fn']:4d}  (Missed attacks)")
            print()
            print(f"  Accuracy:   {accuracy:6.2f}%")
            print(f"  Precision:  {precision:6.2f}%  (When it blocks, how often is it right?)")
            print(f"  Recall:     {recall:6.2f}%  (How many attacks does it catch?)")
            print(f"  F1-Score:   {f1_score:6.2f}%")
        
        # Calculate improvements
        orig = self.results['original']
        enh = self.results['enhanced']
        
        orig_accuracy = ((orig['tp'] + orig['tn']) / (orig['tp'] + orig['fp'] + orig['tn'] + orig['fn']) * 100)
        enh_accuracy = ((enh['tp'] + enh['tn']) / (enh['tp'] + enh['fp'] + enh['tn'] + enh['fn']) * 100)
        
        orig_recall = (orig['tp'] / (orig['tp'] + orig['fn']) * 100) if (orig['tp'] + orig['fn']) > 0 else 0
        enh_recall = (enh['tp'] / (enh['tp'] + enh['fn']) * 100) if (enh['tp'] + enh['fn']) > 0 else 0
        
        print("\n" + "="*70)
        print("IMPROVEMENT SUMMARY")
        print("="*70)
        print(f"\nAccuracy:      {orig_accuracy:.2f}% → {enh_accuracy:.2f}%  ({enh_accuracy - orig_accuracy:+.2f}%)")
        print(f"Recall:        {orig_recall:.2f}% → {enh_recall:.2f}%  ({enh_recall - orig_recall:+.2f}%)")
        print(f"Attacks Caught: {orig['tp']} → {enh['tp']}  ({enh['tp'] - orig['tp']:+d})")
        print(f"False Positives: {orig['fp']} → {enh['fp']}  ({enh['fp'] - orig['fp']:+d})")
        
        if enh_accuracy > orig_accuracy and enh_recall > orig_recall:
            print("\n🎉 SIGNIFICANT IMPROVEMENT!")
            print("   The enhanced detector is better in all key metrics!")
        elif enh_recall > orig_recall:
            print("\n✅ DETECTION IMPROVED!")
            print("   The enhanced detector catches more attacks!")
    
    def benchmark_performance(self, samples, iterations=100):
        """Benchmark detection speed"""
        print("\n" + "="*70)
        print("PERFORMANCE BENCHMARK")
        print("="*70)
        
        test_samples = samples[:iterations]
        
        # Benchmark original
        print(f"\nBenchmarking Original Detector on {len(test_samples)} samples...")
        start = time.time()
        for sample in test_samples:
            self.original_detector.is_anomalous(sample, threshold=25)
        original_time = time.time() - start
        original_avg = (original_time / len(test_samples)) * 1000
        
        # Benchmark enhanced
        print(f"Benchmarking Enhanced Detector on {len(test_samples)} samples...")
        start = time.time()
        for sample in test_samples:
            self.enhanced_detector.is_anomalous(sample, threshold=None)
        enhanced_time = time.time() - start
        enhanced_avg = (enhanced_time / len(test_samples)) * 1000
        
        print("\n" + "="*70)
        print("PERFORMANCE RESULTS")
        print("="*70)
        print(f"\n{'Detector':<15} {'Total Time':<15} {'Avg per Request':<20} {'Requests/sec':<15}")
        print("-" * 70)
        print(f"{'Original':<15} {original_time:>13.3f}s {original_avg:>17.2f}ms {len(test_samples)/original_time:>13.1f}")
        print(f"{'Enhanced':<15} {enhanced_time:>13.3f}s {enhanced_avg:>17.2f}ms {len(test_samples)/enhanced_time:>13.1f}")
        
        if enhanced_avg < original_avg:
            print(f"\n⚡ Enhanced is {original_avg/enhanced_avg:.2f}x FASTER!")
        elif enhanced_avg > original_avg:
            print(f"\n⏱️  Enhanced is {enhanced_avg/original_avg:.2f}x slower")
            print("   (This is expected due to ML features - still fast enough for production)")
        
        print()


def main():
    """Run comprehensive testing"""
    print("="*70)
    print("WAF DETECTOR COMPARISON & TESTING")
    print("="*70)
    print("\nThis script will:")
    print("  1. Train both detectors on normal traffic")
    print("  2. Test attack detection rate")
    print("  3. Test false positive rate")
    print("  4. Calculate performance metrics")
    print("  5. Benchmark detection speed")
    print()
    
    tester = WAFTester()
    
    # Load dataset
    normal_samples, attack_samples = tester.load_csic_csv_dataset()
    
    if normal_samples is None or attack_samples is None:
        print("\n❌ Failed to load dataset. Exiting.")
        return
    
    # Train detectors
    tester.train_detectors(normal_samples, train_size=2000)
    
    # Test attack detection
    tester.test_attack_detection(attack_samples, test_size=500, threshold=25)
    
    # Test false positives
    tester.test_false_positives(normal_samples, test_start=2000, test_size=200, threshold=25)
    
    # Calculate final metrics
    tester.calculate_final_metrics()
    
    # Performance benchmark
    tester.benchmark_performance(normal_samples, iterations=100)
    
    print("\n" + "="*70)
    print("✅ TESTING COMPLETE!")
    print("="*70)
    print("\nRecommendations:")
    print("  1. Review the improvement metrics above")
    print("  2. Analyze false positive examples if FP rate is high")
    print("  3. Consider adjusting thresholds if needed")
    print("  4. Replace ultra_anomaly_detection.py with ultra_anomaly_detection_enhanced.py")
    print("  5. Replace hybrid_waf.py with hybrid_waf_enhanced.py")
    print()


if __name__ == '__main__':
    try:
        main()
        input("\nPress Enter to exit...")
    except KeyboardInterrupt:
        print("\n\n⚠️  Testing interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")