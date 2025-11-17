#!/usr/bin/env python3
"""
Enhanced Rules Generator for WAF
Automatically generates rules from multiple cybersecurity datasets

Sources:
- OWASP Core Rule Set (ModSecurity rules)
- SecLists (attack payloads)
- PayloadsAllTheThings (exploitation payloads)

Usage:
    python enhanced_rules_generator.py

Output:
    rules.py - Ready-to-use rules file
"""

import re
import os
from collections import defaultdict

class RulesGenerator:
    def __init__(self):
        self.patterns = defaultdict(list)
        self.pattern_count = 0
    
    def load_seclists_payloads(self, base_path='datasets/SecLists'):
        """Load attack payloads from SecLists repository"""
        
        print("\n" + "="*70)
        print("LOADING SECLISTS PAYLOADS")
        print("="*70)
        
        payload_files = {
            'SQL Injection': [
                'Fuzzing/SQLi/Generic-SQLi.txt',
                'Fuzzing/SQLi/quick-SQLi.txt',
                'Fuzzing/SQLi/Auth_Bypass.txt',
            ],
            'Cross-Site Scripting': [
                'Fuzzing/XSS/XSS-Jhaddix.txt',
                'Fuzzing/XSS/XSS-BruteLogic.txt',
                'Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt',
            ],
            'Command Injection': [
                'Fuzzing/command-injection-commix.txt',
                'Fuzzing/Unix-Binaries.txt',
            ],
            'Directory Traversal': [
                'Fuzzing/LFI/LFI-Jhaddix.txt',
                'Fuzzing/LFI/LFI-gracefulsecurity-linux.txt',
            ],
        }
        
        for attack_type, files in payload_files.items():
            print(f"\nLoading {attack_type} payloads...")
            count = 0
            
            for file in files:
                filepath = os.path.join(base_path, file)
                if os.path.exists(filepath):
                    payloads = self._load_text_file(filepath)
                    print(f"  - {file}: {len(payloads)} payloads")
                    
                    # Convert top payloads to regex patterns
                    for payload in payloads[:50]:  # Limit per file
                        pattern = self._payload_to_regex(payload)
                        if pattern and len(pattern) < 200:  # Not too long
                            self.patterns[attack_type].append(pattern)
                            count += 1
                else:
                    print(f"  - {file}: NOT FOUND (skipped)")
            
            print(f"  Total loaded: {count} patterns")
    
    def load_owasp_crs_rules(self, base_path='datasets/coreruleset/rules'):
        """Load regex patterns from OWASP Core Rule Set"""
        
        print("\n" + "="*70)
        print("LOADING OWASP CORE RULE SET")
        print("="*70)
        
        rule_files = {
            'REQUEST-942-APPLICATION-ATTACK-SQLI.conf': 'SQL Injection',
            'REQUEST-941-APPLICATION-ATTACK-XSS.conf': 'Cross-Site Scripting',
            'REQUEST-932-APPLICATION-ATTACK-RCE.conf': 'Command Injection',
            'REQUEST-930-APPLICATION-ATTACK-LFI.conf': 'Directory Traversal',
            'REQUEST-931-APPLICATION-ATTACK-RFI.conf': 'Remote File Inclusion',
            'REQUEST-933-APPLICATION-ATTACK-PHP.conf': 'PHP Injection',
        }
        
        for filename, attack_type in rule_files.items():
            filepath = os.path.join(base_path, filename)
            if os.path.exists(filepath):
                patterns = self._parse_modsec_file(filepath)
                print(f"  - {filename}: {len(patterns)} patterns")
                self.patterns[attack_type].extend(patterns)
            else:
                print(f"  - {filename}: NOT FOUND (skipped)")
    
    def load_payloads_all_the_things(self, base_path='datasets/PayloadsAllTheThings'):
        """Load patterns from PayloadsAllTheThings"""
        
        print("\n" + "="*70)
        print("LOADING PAYLOADS ALL THE THINGS")
        print("="*70)
        
        directories = {
            'SQL Injection': 'SQL Injection',
            'Cross-Site Scripting': 'XSS Injection',
            'Command Injection': 'Command Injection',
            'Directory Traversal': 'File Inclusion',
        }
        
        for attack_type, directory in directories.items():
            dir_path = os.path.join(base_path, directory)
            if os.path.exists(dir_path):
                count = self._load_markdown_payloads(dir_path, attack_type)
                print(f"  - {directory}: {count} patterns")
            else:
                print(f"  - {directory}: NOT FOUND (skipped)")
    
    def _load_text_file(self, filepath):
        """Load payloads from text file"""
        payloads = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and len(line) < 200:
                        payloads.append(line)
        except Exception as e:
            print(f"    Error: {e}")
        return payloads
    
    def _load_markdown_payloads(self, dir_path, attack_type):
        """Load payloads from markdown files in directory"""
        count = 0
        try:
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    if file.endswith('.md'):
                        filepath = os.path.join(root, file)
                        # Extract code blocks from markdown
                        payloads = self._extract_code_blocks(filepath)
                        for payload in payloads[:20]:  # Limit per file
                            pattern = self._payload_to_regex(payload)
                            if pattern and len(pattern) < 200:
                                self.patterns[attack_type].append(pattern)
                                count += 1
        except Exception as e:
            print(f"    Error: {e}")
        return count
    
    def _extract_code_blocks(self, filepath):
        """Extract code blocks from markdown file"""
        payloads = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Find code blocks between ```
                code_blocks = re.findall(r'```[\w]*\n(.*?)```', content, re.DOTALL)
                for block in code_blocks:
                    lines = block.strip().split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and len(line) < 200:
                            payloads.append(line)
        except Exception as e:
            pass
        return payloads
    
    def _payload_to_regex(self, payload):
        """Convert payload string to regex pattern"""
        # Escape special regex characters
        pattern = re.escape(payload)
        
        # Make it case-insensitive
        pattern = f"(?i){pattern}"
        
        return pattern
    
    def _parse_modsec_file(self, filepath):
        """Parse ModSecurity rule file and extract regex patterns"""
        patterns = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract @rx patterns
            regex_patterns = re.findall(r'@rx\s+"([^"]+)"', content)
            
            for pattern in regex_patterns:
                # Clean up the pattern
                pattern = pattern.replace('(?i:', '(')
                if len(pattern) < 200:  # Not too long
                    patterns.append(pattern)
        except Exception as e:
            print(f"    Error: {e}")
        
        return patterns
    
    def remove_duplicates(self):
        """Remove duplicate patterns"""
        for attack_type in self.patterns:
            original = len(self.patterns[attack_type])
            self.patterns[attack_type] = list(set(self.patterns[attack_type]))
            removed = original - len(self.patterns[attack_type])
            if removed > 0:
                print(f"  - {attack_type}: Removed {removed} duplicates")
    
    def generate_rules_file(self, output_file='rules.py'):
        """Generate Python rules file"""
        
        print("\n" + "="*70)
        print("GENERATING ENHANCED RULES FILE")
        print("="*70)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('"""\n')
            f.write('Enhanced WAF Rules - Auto-generated\n')
            f.write('\n')
            f.write('Sources:\n')
            f.write('- OWASP Core Rule Set (https://github.com/coreruleset/coreruleset)\n')
            f.write('- SecLists (https://github.com/danielmiessler/SecLists)\n')
            f.write('- PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings)\n')
            f.write('\n')
            f.write('DO NOT EDIT MANUALLY - Regenerate using enhanced_rules_generator.py\n')
            f.write('"""\n\n')
            
            f.write('RULES = {\n')
            
            for attack_type, patterns in sorted(self.patterns.items()):
                # Limit to top 150 patterns per category for performance
                patterns = patterns[:150]
                
                f.write(f'    "{attack_type}": [\n')
                for pattern in patterns:
                    # Escape the pattern for Python string
                    escaped = pattern.replace('\\', '\\\\').replace('"', '\\"')
                    f.write(f'        r"{escaped}",\n')
                f.write('    ],\n\n')
            
            f.write('}\n\n\n')
            
            # Add statistics function
            f.write('def get_rule_statistics():\n')
            f.write('    """Get statistics about the ruleset"""\n')
            f.write('    total_rules = sum(len(patterns) for patterns in RULES.values())\n')
            f.write('    return {\n')
            f.write('        "total_categories": len(RULES),\n')
            f.write('        "total_rules": total_rules,\n')
            f.write('        "rules_per_category": {k: len(v) for k, v in RULES.items()}\n')
            f.write('    }\n\n\n')
            
            # Add main block for testing
            f.write('if __name__ == "__main__":\n')
            f.write('    stats = get_rule_statistics()\n')
            f.write('    print("=" * 70)\n')
            f.write('    print("ENHANCED WAF RULESET STATISTICS")\n')
            f.write('    print("=" * 70)\n')
            f.write('    print(f"Total Categories: {stats[\'total_categories\']}")\n')
            f.write('    print(f"Total Rules: {stats[\'total_rules\']}")\n')
            f.write('    print("\\nRules per category:")\n')
            f.write('    for category, count in sorted(stats[\'rules_per_category\'].items()):\n')
            f.write('        print(f"  {category:40s}: {count:4d} rules")\n')
        
        total = sum(len(p) for p in self.patterns.values())
        print(f"\n✅ Generated {output_file}")
        print(f"   Total patterns: {total}")
        for attack_type, patterns in sorted(self.patterns.items()):
            print(f"   - {attack_type}: {len(patterns)} patterns")
    
    def get_statistics(self):
        """Print statistics about loaded patterns"""
        total = sum(len(patterns) for patterns in self.patterns.values())
        print("\n" + "="*70)
        print("SUMMARY")
        print("="*70)
        print(f"Total patterns loaded: {total}")
        print("\nBreakdown by attack type:")
        for attack_type, patterns in sorted(self.patterns.items()):
            print(f"  - {attack_type:40s}: {len(patterns):4d} patterns")


def main():
    print("="*70)
    print("ENHANCED WAF RULES GENERATOR")
    print("="*70)
    print("\nThis tool generates enhanced WAF rules from multiple sources:")
    print("  1. OWASP Core Rule Set (ModSecurity)")
    print("  2. SecLists (Daniel Miessler)")
    print("  3. PayloadsAllTheThings (swisskyrepo)")
    print()
    
    generator = RulesGenerator()
    
    # Check if datasets exist
    if not os.path.exists('datasets'):
        print("❌ Error: datasets/ directory not found")
        print("\nPlease run setup first:")
        print("  bash setup_datasets.sh")
        print("\nOr clone datasets manually:")
        print("  mkdir -p datasets && cd datasets")
        print("  git clone https://github.com/danielmiessler/SecLists.git")
        print("  git clone https://github.com/coreruleset/coreruleset.git")
        print("  git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git")
        return
    
    # Load from all sources
    try:
        generator.load_seclists_payloads()
    except Exception as e:
        print(f"Error loading SecLists: {e}")
    
    try:
        generator.load_owasp_crs_rules()
    except Exception as e:
        print(f"Error loading OWASP CRS: {e}")
    
    try:
        generator.load_payloads_all_the_things()
    except Exception as e:
        print(f"Error loading PayloadsAllTheThings: {e}")
    
    # Remove duplicates
    print("\n" + "="*70)
    print("REMOVING DUPLICATES")
    print("="*70)
    generator.remove_duplicates()
    
    # Show statistics
    generator.get_statistics()
    
    # Generate file
    generator.generate_rules_file('rules.py')
    
    print("\n" + "="*70)
    print("✅ COMPLETE!")
    print("="*70)
    print("\nNext steps:")
    print("  1. Review rules.py")
    print("  2. Test with: python rules.py")
    print("  3. Replace your rules.py with rules.py")
    print("  4. Restart your WAF application")
    print()


if __name__ == '__main__':
    main()