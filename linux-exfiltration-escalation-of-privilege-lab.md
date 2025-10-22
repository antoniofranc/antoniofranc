# Threat Hunt Report: Linux, escalation of privileges and data exfiltration 

**Analyst**: Antonio Francisco
**Date Completed:** 10/22/2025

## Platforms and Languages Leveraged
- **Microsoft Azure** (Cloud Platform)  
- **Microsoft Sentinel** (SIEM)  
- **Log Analytics Workspace**  
- **Kusto Query Language (KQL)**  
- **Azure Active Directory (Entra ID)**  
- **Windows 10 Virtual Machine**  

##  Scenario

Management suspects that some corporate accounts may be accessed from regions outside of the company’s approved geographic zones, potentially indicating **account sharing or credential compromise**.  
Recent sign-in logs revealed logins from multiple countries within minutes, triggering suspicion of “**impossible travel**” — when a user appears to authenticate from two distant locations in an unrealistic time frame.  

The goal is to **detect and investigate abnormal login activity** by analyzing Azure AD SigninLogs using Microsoft Sentinel, validate true or false positives, and take response actions following the **NIST 800-61 Incident Response Lifecycle**.

### High-Level IoC Discovery Plan

1. Check `SigninLogs` for users authenticating from **multiple geographic locations** within a short period.  
2. Identify patterns of **impossible travel** — logins from different countries/states within 7 days.  
3. Investigate involved accounts for **tool switching** (Portal → CLI), **unusual IPs**, and **authentication errors**.  
4. Validate if detected activity represents **legitimate remote work** or **compromise**.  


---

## Steps Taken

### 1. Queried `SigninLogs` Table for Multiple Regions
Queried Azure AD sign-in data for users authenticating from **more than two unique geographic regions** in a 7-day period.

**Query used to locate events:**

```kql
// Locate Instances of Potential Impossible Travel
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, City, State, Country
| summarize PotentialImpossibleTravelInstances = count () by UserPrincipalName
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```
<div style="display:flex;flex-direction:column;gap:10px">
  <img src="https://res.cloudinary.com/dk3bkl3ji/image/upload/v1760154342/Screenshot_2025-10-10_234316_s71u5u.png">
</div>

---

### 2. Investigated User’s Logon Activity

Used targeted KQL queries to review sign-in locations and timestamps for both accounts.

**Query used to locate event:**

```kql


SigninLogs
| where UserPrincipalName =~ "fb4a5b8c3e2f1a9b8c7d6e5f4a3b2c1d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b@******.com"
| where TimeGenerated between(datetime(2025-09-30 16:00:00) .. datetime(2025-09-30 18:00:00))
| project 
    TimeGenerated,
    AppDisplayName,
    IPAddress,
    Location = strcat(tostring(parse_json(LocationDetails).city), ", ", tostring(parse_json(LocationDetails).state)),
    ResultType
| order by TimeGenerated asc
```
<img width="1436" height="255" alt="image" src="https://github.com/user-attachments/assets/fae5c1f3-b7c0-42ed-8d4a-9dc2a51a1f1f" />


---

### 3. Validated Impossible Travel Case

The second account showed sign-ins 2,400 miles apart (California → Virginia) within 55 minutes.

Time (UTC)	Location	Application	IP Address
4:22 PM	Sonora, CA	Azure Portal	136.175.31.162
4:41 PM	Sonora, CA	Azure Portal	136.175.31.162
5:36 PM	Ashburn, VA	Azure Portal	2600:1010:b1a8:97e8:316e:7602:bba0:1bcf
5:56 PM	Boydton, VA	Azure CLI	74.249.42.6


---

### 4. Confirmed Tool Switching and Multi-Host Access

The attacker first accessed the Azure Portal through a browser, then switched to the Azure CLI, suggesting deeper system access.
Multiple IPs from different providers confirmed the use of proxy/VPN or distributed infrastructure.


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
