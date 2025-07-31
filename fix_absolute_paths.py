#!/usr/bin/env python3
import re

def fix_index_paths():
    """Fix paths in index.html to be relative instead of absolute."""
    with open('public/index.html', 'r') as f:
        content = f.read()
    
    # Replace absolute paths with relative paths
    # For index.html in the root, we don't need any ../ prefix
    content = re.sub(r'hx-get="/vuln-bot/fragments/', r'hx-get="fragments/', content)
    content = re.sub(r'hx-get="/vuln-bot/data/', r'hx-get="data/', content)
    
    # Also fix the CSV export button
    content = re.sub(r'"/vuln-bot/data/vulnerabilities.csv"', r'"data/vulnerabilities.csv"', content)
    
    with open('public/index.html', 'w') as f:
        f.write(content)
    print("Fixed: public/index.html")

def fix_fragment_paths():
    """Fix paths in fragment files to be relative."""
    import os
    
    # Fix all HTML files in fragments directory
    for root, dirs, files in os.walk('public/fragments'):
        for file in files:
            if file.endswith('.html'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r') as f:
                    content = f.read()
                
                # For files in fragments/, we need to go up one level to reach fragments/
                # So /vuln-bot/fragments/ becomes ../
                content = re.sub(r'hx-get="/vuln-bot/fragments/', r'hx-get="../', content)
                
                # For data, we need to go up two levels: ../../data/
                content = re.sub(r'hx-get="/vuln-bot/data/', r'hx-get="../../data/', content)
                
                with open(filepath, 'w') as f:
                    f.write(content)
                print(f"Fixed: {filepath}")

if __name__ == "__main__":
    print("Fixing absolute paths to relative paths...")
    fix_index_paths()
    fix_fragment_paths()
    print("All paths have been updated!")