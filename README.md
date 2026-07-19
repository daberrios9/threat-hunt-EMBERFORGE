# Threat Hunt Report: SECOND VECTOR

**Date:** June 2026

## Platforms and Tools Used
- **Platform:** Microsoft Defender for Endpoint (MDE), Log Analytics Workspace, Windows 10 host `anthony-001`
- **Languages & Tools:** Kusto Query Language (KQL) 

---

## Scenario Summary


---

## 🔎 Flag Analysis & Findings

### 🏁 Flag 1 – The Compromised Principal
- **Answer:** `m.smith@lognpacific.org`
- **Discovery:** By reviewing Microsoft Defender XDR, I identified the affected account by opening 87241 through the Evidence and Response pane. The incident evidence listed the impacted user as a UPN rather than just a display name, which confirmed the account involved was m.smith@lognpacific.org. This UPN became the primary identity pivot for the rest of the investigation.

![image](https://github.com/user-attachments/assets/959b95b7-341a-46fe-9f00-cc1dc0e11393)


---

Now we want to identify the program or service responsible for dropping the malicious file into the disk. It didn't just spawn out of thin air.  This validates the delivery mechanism of the dropper and supports behavioral indicators of compromise, particularly in directories often used by malware.

### 🏁 Flag 2 – The Flagged Source
- **Answer:** `103.69.224.136 `
- **Discovery:** I reviewed the incident timeline to identify the source of the suspicious sign-in. The event showed that the login originated from 103.69.224.136, which became the main indicator I used to correlate activity across the different log sources during the investigation.
`"csc.exe" /noconfig /fullpaths @"C:\Users\4nth0ny!\AppData\Local\Temp\c5gy0jzg\c5gy0jzg.cmdline"'`

![image](https://github.com/user-attachments/assets/49de3cba-67fe-4d3a-ab15-1e5a5bd1b9f0)


---

### 🏁 Flag 3 – The Client OS
- **Answer:** `Linux`
- **Discovery:** I examined the user-agent string associated with the flagged sign-in in the incident timeline to determine the operating system used during the login. The user-agent identified the client operating system as Linux, providing additional context about the environment the attacker used to access the account.

---

### 🏁 Flag 4 – The Stored Detection Type
- **Answer:** `anonymizedIPAddress`
- **Notes:** We now need to identify whether any artifact was dropped that indicates keylogger behavior. Created shortly after BitSentinelCore execution, placed in the AppData Startup folder. This confirms credential harvesting or surveillance behavior linked to the fake antivirus binary.

- **Query Used:**

```kql
DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp between (datetime(2025-05-07T01:59:00Z) .. datetime(2025-05-07T02:10:00Z))
| where InitiatingProcessFileName in~ ("BitSentinelCore.exe", "explorer.exe", "csc.exe", "svchost.exe", "powershell.exe", "cmd.exe", "wscript.exe", "rundll32.exe")
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

Note: An LNK file is a Windows shortcut, which points to and is used to open another file, folder, or application. It contains information about the object to which it points, including the object's type, location, and filename.

---

### 🏁 Flag 5 – The Audit Verdict 
- **Answer:** `dismissed`
- **Key Detail:** We need to determine if the malware established persistence via the Windows Registry. This reveals how the malware achieves persistence across system reboots or logins, helping track long-term infection. The above key was created by BitSentinelCore to auto-run malware at logon.

This is a step that was especially painfully slow. I didn't know why I could not find registry information even thought I have used it before, just to realize that if you look at the DeviceRegistryEvents in Microsoft Sentinel, it doesn't exist. This table only exists in the Microsoft Defender for Endpoint portal, somehow. Way to go, Microsoft. 

```kql
DeviceRegistryEvents 
| where DeviceName == "anthony-001"
| where InitiatingProcessFileName == "bitsentinelcore.exe"
```

![image](https://github.com/user-attachments/assets/6603bde9-ca46-4b6e-87f6-09cb430c0190)

The fact that there was more than a thousand entries on registry changes also added to the bulk of having to sort through all of the noise to find a true positive.

![image](https://github.com/user-attachments/assets/e9b758dd-61e3-4880-9643-89e88498940c)


---

### 🏁 Flag 6 – Live Exposure
- **Answer:** `Enabled`
- **Notes:** Going through the logs, I could see that there was Windows Task Scheduler Activity, so we want to verify that this was indeed malicious. Without detecting this task,you might miss that the system stays infected beyond just running the dropper once. This task was scheduled to run daily, providing long-term persistence. The name mimics legitimate telemetry functions to evade detection.

```kql
let Timespan = datetime("2025-05-07T02:06:51.0000000Z");
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where TimeGenerated between (Timespan - 10m .. Timespan + 15m)
| where ProcessCommandLine has_any ("schtasks", "/create", "/sc", "daily", "Task", "BitSentinel", "systemreport")
```

This query was useful to find anything that had to do with scheduled tasks. I didn't know which keyword it would have, so it was smart to include them all. 

![image](https://github.com/user-attachments/assets/d7cc9d01-fbbe-4116-8b98-a9bc832450e5)


---

### 🏁 Flag 7 – How the Session Beat MFA
- **Answer:** `singleFactorAuthentication`
- **Notes:** Clear lateral process relationship confirming scheduled task was malware-controlled.

---

### 🏁 Flag 8 – The Control Surface That Let Them In
- **Answer:** `One Outlook Web`
- **Notes:** This timestamp was confirmed to align with malware execution, file drop, and registry modification—all tracing back to BitSentinelCore.exe.

---
### 🏁 Flag 9 - Failed Attempts Before Entry
- **Answer:** `2`
---

### 🏁 Flag 10 - Blast Radius of One Token
- **Answer:** `7`
  
---

### 🏁 Flag 11 - One Caustious Session
- **Answer:** `005d431a-380b-1f5e-e554-16d5010dc28e`

---

### 🏁 Flag 12 - MFA Posture Profiling
- **Answer:** `userRegistrationDetails`

---

### 🏁 Flag 13 - Group Enumeration
- **Answer:** `/me/memberOf`

---

### 🏁 Flag 14 - The Fraudulent Request 
- **Answer:** `Updated Banking Details - Pacific IT Monthly`

---

### 🏁 Flag 15 - The Threa They Mined
- **Answer:** ``

---

### 🏁 Flag 16 - The Fraud Target 
- **Answer:** `j.reynolds@lognpacific.org`

---

### 🏁 Flag 17 - Second Channel Reinforcement 
- **Answer:** `Microsoft Teams`

---

### 🏁 Flag 18 - The Concealment Rule 
- **Answer:** `Invoice Processing`

---

### 🏁 Flag 19 - Where the Hidden Male Goes 
- **Answer:** `hide mail without raising suspicion`

--- 

### 🏁 Flag 20 - The Exfiltration Rule 
- **Answer:** `merovingian1337@proton.me`

---

### 🏁 Flag 21 - Who Both Rules Target 
- **Answer:** `hide replies to the fraudulent payment request`

---

### 🏁 Flag 22 - The Exfil Operation
- **Answer:** `FileDownloaded`

---

### 🏁 Flag 23 - Volume Taken 
- **Answer:** `3`

---

### 🏁 Flag 24 - The Credential Document 
- **Answer:** `VPN-Access-Credentials.txt`

---

### 🏁 Flag 25 - The Vault Pointer 
- **Answer:** `yomark.pdf`

---

### 🏁 Flag 26 - Disprove the Innocent Explanation
- **Answer:** `0`

---

### 🏁 Flag 27 - Catch the Plant 
- **Answer:** `Microsoft Flow Portal`

---

### 🏁 Flag 28 - The Cause Behind the Forward 
- **Answer:** `MicrosoftGraphActivityLogs`

---

### 🏁 Flag 29 - Prove It With Sequence
- **Answer:** `The Graph call`

---

### 🏁 Flag 30 - The Automation Source IP
- **Answer:** `20.150.129.194`

---

### 🏁 Flag 31 - The Automation Source Identity
- **Answer:** `7ab7862c-4c57-491e-8a45-d52a7e023983`

---

### 🏁 Flag 32 - Name the Abused Service
- **Answer:** `Power Automate`

---

### 🏁 Flag 33 - One Actor, Every Source
- **Answer:** `7`

---

### 🏁 Flag 34 - Containment Ordering 
- **Answer:** `Revoke user sessions`

---

### 🏁 Flag 35 - Where the Flow Is Removed
- **Answer:** `Power Platform admin center`

---

### 🏁 Flag 36 - The Control That Never Fired
- **Answer:** `Conditional Access was not applied, allowing the legacy single-factor client path to bypass policy.`

---

### 🏁 Flag 37 - Why Revoke Before Reset 
- **Answer:** `Refresh tokens survive a password reset; revoke user sessions first.`
