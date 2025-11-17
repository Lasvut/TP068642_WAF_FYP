#!/usr/bin/env python3
"""
Find and Fix Malformed Regex Patterns in rules.py

This script will:
1. Find all patterns with regex errors
2. Attempt to fix common issues (unbalanced parentheses)
3. Create a clean version of rules.py
"""

import re
import sys

def test_pattern(pattern):
    """Test if a regex pattern is valid"""
    try:
        re.compile(pattern, re.IGNORECASE)
        return True, None
    except re.error as e:
        return False, str(e)

def fix_unbalanced_parentheses(pattern):
    """Attempt to fix unbalanced parentheses"""
    # Count opening and closing parentheses
    open_count = pattern.count('(')
    close_count = pattern.count(')')
    
    # Escape unescaped parentheses that aren't part of groups
    fixed = pattern
    
    # Simple fix: if more ( than ), add ) at end
    if open_count > close_count:
        fixed = pattern + ')' * (open_count - close_count)
    # If more ) than (, remove extra )
    elif close_count > open_count:
        # This is trickier - try escaping the extras
        fixed = pattern.replace(')', '\\)', close_count - open_count)
    
    # Test if fix worked
    is_valid, _ = test_pattern(fixed)
    if is_valid:
        return fixed
    
    # If still broken, try escaping all parentheses
    fixed = pattern.replace('(', '\\(').replace(')', '\\)')
    is_valid, _ = test_pattern(fixed)
    if is_valid:
        return fixed
    
    # Give up - return original
    return pattern

def analyze_rules():
    """Analyze rules.py for malformed patterns"""
    
    print("=" * 70)
    print("ANALYZING RULES.PY FOR MALFORMED PATTERNS")
    print("=" * 70)
    print()
    
    try:
        from rules import RULES
    except ImportError:
        print("❌ Error: Could not import rules.py")
        print("   Make sure you're running this from your project directory")
        return
    
    total_patterns = 0
    bad_patterns = []
    
    print("Testing all patterns...\n")
    
    for attack_type, patterns in RULES.items():
        print(f"Checking {attack_type}...")
        
        for i, pattern in enumerate(patterns):
            total_patterns += 1
            is_valid, error = test_pattern(pattern)
            
            if not is_valid:
                bad_patterns.append({
                    'attack_type': attack_type,
                    'index': i,
                    'pattern': pattern,
                    'error': error
                })
                print(f"  ❌ Pattern {i}: {error}")
                print(f"     {pattern[:80]}...")
    
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"\nTotal patterns tested: {total_patterns}")
    print(f"Valid patterns: {total_patterns - len(bad_patterns)}")
    print(f"Malformed patterns: {len(bad_patterns)}")
    
    if bad_patterns:
        print("\n" + "=" * 70)
        print("MALFORMED PATTERNS DETAILS")
        print("=" * 70)
        
        for bp in bad_patterns:
            print(f"\nAttack Type: {bp['attack_type']}")
            print(f"Pattern Index: {bp['index']}")
            print(f"Error: {bp['error']}")
            print(f"Pattern: {bp['pattern'][:100]}")
            
            # Try to fix
            fixed = fix_unbalanced_parentheses(bp['pattern'])
            is_valid, _ = test_pattern(fixed)
            
            if is_valid and fixed != bp['pattern']:
                print(f"✅ Auto-fix available:")
                print(f"   Fixed: {fixed[:100]}")
            else:
                print(f"⚠️  Could not auto-fix - manual correction needed")
        
        # Offer to create fixed version
        print("\n" + "=" * 70)
        print("FIX OPTIONS")
        print("=" * 70)
        print("\n1. Create rules_fixed.py with auto-fixes")
        print("2. Just show the problematic patterns")
        print("3. Exit")
        
        choice = input("\nYour choice (1-3): ").strip()
        
        if choice == '1':
            create_fixed_rules(RULES, bad_patterns)
        elif choice == '2':
            print("\nProblematic patterns saved above. Fix them manually in rules.py")
    else:
        print("\n✅ All patterns are valid!")

def create_fixed_rules(rules, bad_patterns):
    """Create a fixed version of rules.py"""
    
    print("\nCreating rules_fixed.py...")
    
    # Create a mapping of bad patterns to fixed ones
    fixes = {}
    for bp in bad_patterns:
        key = (bp['attack_type'], bp['index'])
        fixed = fix_unbalanced_parentheses(bp['pattern'])
        is_valid, _ = test_pattern(fixed)
        
        if is_valid:
            fixes[key] = fixed
        else:
            # If can't fix, just comment it out
            fixes[key] = None
    
    # Write new file
    with open('rules_fixed.py', 'w', encoding='utf-8') as f:
        f.write('"""\n')
        f.write('Fixed WAF Rules - Auto-generated\n')
        f.write('Malformed patterns have been fixed or removed\n')
        f.write('"""\n\n')
        
        f.write('RULES = {\n')
        
        for attack_type, patterns in rules.items():
            f.write(f'    "{attack_type}": [\n')
            
            for i, pattern in enumerate(patterns):
                key = (attack_type, i)
                
                if key in fixes:
                    if fixes[key] is not None:
                        # Use fixed pattern
                        escaped = fixes[key].replace('\\', '\\\\').replace('"', '\\"')
                        f.write(f'        r"{escaped}",  # AUTO-FIXED\n')
                    else:
                        # Comment out unfixable pattern
                        escaped = pattern.replace('\\', '\\\\').replace('"', '\\"')
                        f.write(f'        # r"{escaped}",  # BROKEN - COMMENTED OUT\n')
                else:
                    # Keep original
                    escaped = pattern.replace('\\', '\\\\').replace('"', '\\"')
                    f.write(f'        r"{escaped}",\n')
            
            f.write('    ],\n\n')
        
        f.write('}\n')
    
    print("✅ Created rules_fixed.py")
    print("\nTo use the fixed rules:")
    print("  1. Backup current rules: cp rules.py rules_backup.py")
    print("  2. Replace with fixed: cp rules_fixed.py rules.py")
    print("  3. Restart your Flask app")
    print()

if __name__ == '__main__':
    try:
        analyze_rules()
    except KeyboardInterrupt:
        print("\n\nCancelled by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
