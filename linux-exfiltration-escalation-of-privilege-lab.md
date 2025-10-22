# Threat Hunt Report: Linux, escalation of privileges and data exfiltration 

**Analyst**: Antonio Francisco

**Date Completed:** 10/22/2025



##  Scenario

Company A has been noticing some PII information about employees might be getting leaked because of recent phishing attempts that have been perpetrated. Such information includes address, email address, and phone number. All of this information is stored on a linux server as a hidden file where only the root/sudo users have read and write access. There was a report by another employee the other day of a fellow employee messing with the computer while the root administrator was in the bathroom. The company has decided to investigate this. 


---

## Steps Taken

### 1. Searched the DeviceFileEvents

I searched the `DeviceFileEvents` table for file activity during the suspected incident window. Two suspicious files named `super_secret_script.sh` were observed: one created at `2025-10-21T23:23:50.03483Z` and a later activity at `2025-10-21T23:59:46.704196Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName contains "Iclab"
| where ActionType == "FileCreated"
| order by Timestamp asc
```
<img width="1892" height="755" alt="Screenshot 2025-10-21 220336" src="https://github.com/user-attachments/assets/578c63cd-87c8-42a8-a915-4db6734c006e" />


---

### 2. Suspicious Script Identification

While examining `DeviceFileEvents` for activity during the incident window, two events for `super_secret_script.sh` were observed: The first event at `2025-10-21T23:23:50.03483Z` shows use of the `touch` command (file creation on Linux); the second at `2025-10-21T23:59:46.704196Z` shows `nano` (a command-line editor), indicating the file was opened and modified. 

**Query used to locate event:**

```kql
DeviceFileEvents
| where DeviceName contains "Iclab" and ActionType == "FileCreated"
| where FileName contains "super_secret_script.sh"
| project Timestamp, InitiatingProcessCommandLine
| sort by Timestamp asc
```
<img width="777" height="108" alt="Screenshot 2025-10-21 224709" src="https://github.com/user-attachments/assets/9bf1182e-9c7a-4796-977e-f41f746bf410" />




---

### 3. Privilege Escalation Detection

Following the file modification, the `DeviceProcessEvents` table shows execution of the command `usermod -aG sudo john_bolas`. This command appends the account `john_bolas` to the `sudo` group on Linux systems, effectively granting that account administrative (root) privileges. The occurrence of this command immediately after modification of `super_secret_script.sh` is highly suspicious and consistent with an attacker escalating privileges to establish persistent, privileged access on the host.

```kql
DeviceFileEvents
| where DeviceName contains "Iclab"
| where ActionType == "FileCreated"
| where InitiatingProcessCommandLine contains "usermod"
| project Timestamp, ActionType, DeviceName, InitiatingProcessCommandLine
| order by Timestamp asc
```
<img width="780" height="110" alt="image" src="https://github.com/user-attachments/assets/3b1b25a5-73e3-41e9-b748-f09cc183dc4a" />




---

### 4. Searched the DeviceProcessEvents Table for Script execution and suspected data exfiltration

I searched the DeviceProcessEvents table for evidence of script execution. At `2025-10-22T00:00:41.464697Z` the host executed: `/bin/bash ./super_secret_script.sh`
Immediately following this execution, the `InitiatingProcessCommandLine` contains multiple commands, including an Azure CLI `az storage blob upload` invocation with an account name, key, and container identifier. The presence of an authenticated Azure Storage upload command directly after the script run is strong evidence that data was collected and transmitted to external Azure storage.

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2025-10-21T23:59:46.704196Z)
| where DeviceName contains "Iclab"
| project Timestamp, DeviceName, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc
```
<img width="1823" height="727" alt="Screenshot 2025-10-22 001450" src="https://github.com/user-attachments/assets/e5a1b66b-31e2-45c8-8b96-0bfcb412eed4" />

---

## Chronological Event Timeline 

### 1. Suspicious Login Detected

- Timestamp: 2025-09-30T21:22Z

- Event: Multiple logins detected for same user across U.S. East and West regions.

- Action: Alert triggered by Sentinel analytics rule.

### 2. Investigation Initiated

- Timestamp: 2025-09-30T21:35Z

- Action: Security analyst (Antonio Francisco) began KQL investigation on affected user.

### 3. Impossible Travel Confirmed

- Timestamp: 2025-09-30T21:56Z

- Event: Authentication events from Sonora, CA and Ashburn, VA within 55 minutes.

- Conclusion: Logically and physically impossible.

### 4. Containment Actions Executed

- Timestamp: 2025-09-30T22:05Z

- Actions:

Disabled account fb4a5b8c3e2f1a9b8c7d6e5f4a3b2c1d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b@******.com

Revoked credentials and active sessions

Management notified

### 5. Post-Incident Review

- Timestamp: 2025-10-02T15:00Z

- Action: Reviewed CLI activity, rotated credentials, and implemented new geo-fencing policies.
 

---

## Summary

The Impossible Travel Detection rule in Microsoft Sentinel successfully identified a real account compromise.
The attacker leveraged valid credentials to access the Azure Portal from geographically distant regions and escalated to command-line access via the Azure CLI.

Findings:

- 1 True Positive (Critical)

- Use of multiple IPs and tools consistent with lateral movement

- Detection logic effective and repeatable


---

## Response Taken

- Compromised account disabled immediately

- Tokens revoked and MFA enforced for all service accounts

- Management notified of confirmed credential compromise

- Enhanced Sentinel queries and policies deployed to reduce false positives

---
