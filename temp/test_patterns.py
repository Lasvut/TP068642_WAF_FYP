import re
import sys
sys.path.insert(0, 'C:\\Users\\marti\\OneDrive\\Documents\\School\\Visual Studio Code')
from rules import RULES

print("Testing all regex patterns for errors...\n")

problematic_patterns = []

for attack_type, patterns in RULES.items():
    for i, pattern in enumerate(patterns):
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            problematic_patterns.append({
                'attack_type': attack_type,
                'index': i,
                'pattern': pattern,
                'error': str(e)
            })
            print(f"❌ ERROR in {attack_type}[{i}]:")
            print(f"   Error: {e}")
            print(f"   Pattern: {pattern[:200]}")
            print()

if problematic_patterns:
    print(f"\n{'='*70}")
    print(f"Found {len(problematic_patterns)} problematic patterns!")
    print(f"{'='*70}\n")
    
    for p in problematic_patterns:
        print(f"Category: {p['attack_type']}")
        print(f"Index: {p['index']}")
        print(f"Error: {p['error']}")
        print(f"Pattern: {p['pattern'][:200]}")
        print("-" * 70)
else:
    print("\n✅ All patterns are valid!")
