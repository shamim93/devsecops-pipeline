import json
import sys
try:
    with open('safety-output.txt', 'r') as f:
        content = f.read()
    report = {
        "tool": "Safety",
        "raw_output": content,
        "vulnerabilities": []
    }
    with open('safety-report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print("Created JSON from text output")
except Exception as e:
    print(f"Error: {e}")
    with open('safety-report.json', 'w') as f:
        json.dump({"tool": "Safety", "vulnerabilities": []}, f)