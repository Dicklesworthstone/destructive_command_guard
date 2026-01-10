import os
import re
import datetime

PACKS_DIR = "src/packs"
OUTPUT_FILE = "docs/pattern_audit.md"

# Regex to find macro calls: safe_pattern!(...) or destructive_pattern!(...)
# We need to handle multi-line calls.
MACRO_RE = re.compile(r'(safe|destructive)_pattern!\s*\(\s*(?:("[^"].*?")\s*,\s*)?r(#*)"(.*?)"\3', re.DOTALL)

# Regex to detect fancy features
FANCY_RE = re.compile(r'\(\?=|(?<!\\)\(?!|\(\?<=|\(\?<!|(?<!\\)\\[1-9]')

def scan_file(filepath):
    try:
        with open(filepath, 'r') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return []

    findings = []
    for match in MACRO_RE.finditer(content):
        kind = match.group(1)
        name_quoted = match.group(2)
        raw_regex = match.group(4)
        
        name = name_quoted.strip('"') if name_quoted else "UNNAMED"
        
        # Check for fancy features
        fancy_match = FANCY_RE.search(raw_regex)
        if fancy_match:
            findings.append({
                "kind": kind,
                "name": name,
                "regex": raw_regex,
                "reason": f"Found '{fancy_match.group(0)}'"
            })
    return findings

def main():
    all_findings = {}
    
    for root, dirs, files in os.walk(PACKS_DIR):
        for file in files:
            if file.endswith(".rs"):
                path = os.path.join(root, file)
                findings = scan_file(path)
                if findings:
                    all_findings[path] = findings

    # Write report
    with open(OUTPUT_FILE, 'w') as f:
        f.write(f"# Pattern Audit Report\n")
        f.write(f"Generated: {datetime.datetime.now().isoformat()}\n\n")
        for path in sorted(all_findings.keys()):
            f.write(f"## `{path}`\n\n")
            f.write("| Kind | Name | Reason | Regex Preview |\n")
            f.write("|------|------|--------|---------------|\n")
            for item in all_findings[path]:
                # Escape pipe for markdown table
                preview = item['regex'].replace('|', '\\|')
                if len(preview) > 60:
                    preview = preview[:57] + "..."
                f.write(f"| {item['kind']} | `{item['name']}` | {item['reason']} | `{preview}` |\n")
            f.write("\n")

if __name__ == "__main__":
    main()
