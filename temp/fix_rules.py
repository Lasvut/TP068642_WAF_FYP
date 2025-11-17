import re

# Read the rules file
with open(r'C:\Users\marti\OneDrive\Documents\School\Visual Studio Code\rules.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Define fixes for each problematic pattern
fixes = [
    # Fix 1: Cross-Site Scripting[7]
    (r'r"\\(\\?i\\)<svg\\\\ onload=prompt%26%230000000040document\\\\.domain\\\\\\)>",',
     r'r"(?i)<svg\\ onload=prompt%26%230000000040document\\.domain>",'),
    
    # Fix 2: Cross-Site Scripting[24]  
    (r'r"\\(\\?i\\)fetch\\\\\\(\'https://<SESSION>\\\\.burpcollaborator\\\\.net\',\\\\ \\\\\\{",',
     r'r"(?i)fetch\\(\'https://.*\\.burpcollaborator\\.net\',",'),
    
    # Fix 3: Cross-Site Scripting[31]
    (r'r"\\(\\?i\\)\\\\\\"\\\\\\);",',
     r'r"(?i)\\\"",'),
    
    # Fix 4: Cross-Site Scripting[90]
    (r'r"\\(\\?i\\)B=C\\\\\\(b,c,b\\\\\\);\\\\\\$evalAsync\\\\\\(\\\\\\\"",',
     r'r"(?i)B=C\\(b,c,b\\);\\$evalAsync",'),
    
    # Fix 5: Cross-Site Scripting[93]
    (r'r"\\(\\?i\\)\\\\\\}\\\\\\);",',
     r'r"(?i)\\}",'),
    
    # Fix 6: Cross-Site Scripting[104]
    (r'r"\\(\\?i\\)<svg\\\\ onload=prompt%26%23x000000028;document\\\\.domain\\\\\\)>",',
     r'r"(?i)<svg\\ onload=prompt%26%23x000000028;document\\.domain>",'),
    
    # Fix 7: SQL Injection[29]
    (r'r"\\(\\?i\\)\\\\\\-\\\\\\-\\\\ May\\\\ need\\\\ CAST\\\\\\(xml2clob\\\\\\(…\\\\ AS\\\\ varchar\\\\\\(500\\\\\\)\\\\\\)\\\\ to\\\\ display\\\\ the\\\\ result\\\\\\.",',
     r'r"(?i)\\-\\-\\ May\\ need\\ CAST\\ with\\ xml2clob\\ and\\ varchar",'),
]

# Apply fixes
fixed_content = content
for old_pattern, new_pattern in fixes:
    fixed_content = re.sub(old_pattern, new_pattern, fixed_content, flags=re.MULTILINE)

# Also do direct string replacements for safety
direct_replacements = [
    ('r"(?i)<svg\\ onload=prompt%26%230000000040document\\.domain\\)>"', 
     'r"(?i)<svg\\ onload=prompt%26%230000000040document\\.domain>"'),
    
    ('r"(?i)fetch\\(\'https://<SESSION>\\.burpcollaborator\\.net\',\\ \\{"',
     'r"(?i)fetch\\(\'https://.*\\.burpcollaborator\\.net\'"'),
    
    ('r"(?i)\\\"\\);"',
     'r"(?i)\\\""'),
    
    ('r"(?i)B=C\\(b,c,b\\);\\$evalAsync\\\""',
     'r"(?i)B=C\\(b,c,b\\);\\$evalAsync"'),
    
    ('r"(?i)\\}\\);"',
     'r"(?i)\\}"'),
    
    ('r"(?i)<svg\\ onload=prompt%26%23x000000028;document\\.domain\\)>"',
     'r"(?i)<svg\\ onload=prompt%26%23x000000028;document\\.domain>"'),
    
    ('r"(?i)\\-\\-\\ May\\ need\\ CAST\\(xml2clob\\(\u2026\\ AS\\ varchar\\(500\\)\\)\\ to\\ display\\ the\\ result\\."',
     'r"(?i)\\-\\-\\ May\\ need\\ CAST\\ with\\ xml2clob\\ and\\ varchar"'),
]

for old, new in direct_replacements:
    if old in fixed_content:
        fixed_content = fixed_content.replace(old, new)
        print(f"✓ Fixed: {old[:60]}...")

# Write the fixed content back
with open(r'C:\Users\marti\OneDrive\Documents\School\Visual Studio Code\rules.py', 'w', encoding='utf-8') as f:
    f.write(fixed_content)

print("\n✅ Rules file has been fixed!")
print("\nNow testing all patterns...")

# Test all patterns
from rules import RULES

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

if problematic_patterns:
    print(f"\n❌ Still found {len(problematic_patterns)} problematic patterns:")
    for p in problematic_patterns:
        print(f"   {p['attack_type']}[{p['index']}]: {p['error']}")
else:
    print("\n✅ All patterns are now valid!")
