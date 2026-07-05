# Threat Hunt Report: SECOND VECTOR

**Date:** June 2026

## Platforms and Tools Used
- **Platform:** Microsoft Defender for Endpoint (MDE), Log Analytics Workspace, Windows 10 host `anthony-001`
- **Languages & Tools:** Kusto Query Language (KQL) 

---

## Scenario Summary


---

## 🔎 Flag Analysis & Findings

### 🏁 Flag 1 – Fake Antivirus Dropper
- **Answer:** `BitSentinelCore.exe`
- **Discovery:** Located in `C:\ProgramData\`, the file was confirmed as the fake antivirus that launched the attack chain. At this point of the hunt, we just know that BitSentinelCore.exe was launched from explorer.exe, this means, the user manually clicked on it. I couldn't get any hits for the hash of this file in VirusTotal, so it must be a polymorphic malware (That changes a little bit every time it executes).

```kql
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName == "BitSentinelCore.exe"
| project Timestamp, FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName, AccountName
| order by Timestamp asc
```

![image](https://github.com/user-attachments/assets/959b95b7-341a-46fe-9f00-cc1dc0e11393)


---

Now we want to identify the program or service responsible for dropping the malicious file into the disk. It didn't just spawn out of thin air.  This validates the delivery mechanism of the dropper and supports behavioral indicators of compromise, particularly in directories often used by malware.

### 🏁 Flag 2 – How was it dropped?
- **Answer:** `csc.exe`
- **Discovery:** BitSentinelCore.exe was created via the C# compiler (`csc.exe`), a signed Microsoft binary abused by attackers. This was found by looking at the records of the timeline events around the date that this was suspected to happen. We can observe that csc.exe was who created BitSentinelCore.exe, and it did so with a very sketchy looking file path which was randomized on purpose to avoid detection and deceive the analyst in a mountain of logs:

`"csc.exe" /noconfig /fullpaths @"C:\Users\4nth0ny!\AppData\Local\Temp\c5gy0jzg\c5gy0jzg.cmdline"'`

![image](https://github.com/user-attachments/assets/49de3cba-67fe-4d3a-ab15-1e5a5bd1b9f0)


---

### 🏁 Flag 3 – Initial Execution Verification
- **Answer:** `BitSentinelCore.exe`
- **Notes:** We want to verify whether the dropped malicious file was manually executed by the user or attacker. Execution of the file marks the start of the malicious payloads being triggered, indicating user interaction or attacker initiation. Execution appeared manual via `explorer.exe`, indicating user interaction. Refer to screenshot on flag 1 for query and results.
- **Key Timestamp:** `2025-05-07T02:00:36.794406Z`

---

### 🏁 Flag 4 – Keylogger File Dropped
- **Answer:** `systemreport.lnk`
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

### 🏁 Flag 5 – Registry Persistence
- **Answer:** `HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
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

### 🏁 Flag 6 – Scheduled Task Created
- **Answer:** `UpdateHealthTelemetry`
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

### 🏁 Flag 7 – Process Spawn Chain
- **Answer:** `BitSentinelCore.exe -> cmd.exe -> schtasks.exe`
- **Notes:** Clear lateral process relationship confirming scheduled task was malware-controlled.

---

### 🏁 Flag 8 – Root Cause Timestamp
- **Answer:** `2025-05-07T02:00:36.794406Z`
- **Notes:** This timestamp was confirmed to align with malware execution, file drop, and registry modification—all tracing back to BitSentinelCore.exe.

---
