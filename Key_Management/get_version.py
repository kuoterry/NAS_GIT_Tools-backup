import re

with open("key_management.py", encoding="utf-8") as f:
    text = f.read()

match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
if match:
    print(match.group(1))
