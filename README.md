# threat-hunt-EMBERFORGE
# write_readme.py
# Generates a README.md file with the "Threat Hunt: EMBERFORGE" template in Markdown.

TEMPLATE = """# Threat Hunt: EMBERFORGE

## Scenario
[Describe the threat scenario, adversary goals, TTPs, and scope of the hunt.]

## Environment Details
- Environment name / lab:
- OS types & versions:
- Network topology (brief):
- Data sources available (e.g., Microsoft Sentinel, Elastic, Splunk, Sysmon, Windows Event Logs, DNS, Proxy, EDR):
- Tools used (e.g., Kusto Query Explorer, Elastic Kibana, Wireshark, Velociraptor):
- Time window for hunt:
- Assumptions & limitations:

---

## Flags (Total: 44)

### Flag 1
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 2
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 3
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 4
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 5
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 6
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 7
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 8
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 9
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 10
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 11
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 12
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 13
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 14
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 15
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 16
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 17
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 18
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 19
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 20
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 21
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 22
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 23
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 24
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 25
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 26
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 27
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 28
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 29
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 30
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 31
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 32
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 33
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 34
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 35
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 36
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 37
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 38
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 39
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 40
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 41
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 42
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 43
- Objective:
- Finding:
- KQL Query:
- Notes:

### Flag 44
- Objective:
- Finding:
- KQL Query:
- Notes:

---

## Conclusion
[Summarize key discoveries, impact, recommended mitigations, lessons learned, and next steps.]

---
"""

def write_readme(path="README.md"):
    with open(path, "w", encoding="utf-8") as f:
        f.write(TEMPLATE)
    print(f"Wrote template to {path}")

if __name__ == "__main__":
    write_readme()

