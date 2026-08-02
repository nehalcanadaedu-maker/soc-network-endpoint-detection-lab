# SOC Incident Report
## Controlled RDP-to-C2 and Data-Transfer Investigation — August 2, 2026

**Environment:** Isolated VirtualBox home lab  
**Analyst:** Nehal Patel  
**Incident date:** August 2, 2026  
**Classification:** Controlled security simulation  
**Production-equivalent severity:** High  

> This report documents a harmless simulation conducted only inside an isolated home lab. No real organization, external system, or production data was targeted.

---

## Navigation

- [1. Executive Summary](#1-executive-summary)
- [2. Incident Scope](#2-incident-scope)
- [3. Chronological Timeline](#3-chronological-timeline)
- [4. Evidence and Findings](#4-evidence-and-findings)
  - [4.1 Network Reconnaissance](#41-network-reconnaissance)
  - [4.2 Failed RDP Authentication](#42-failed-rdp-authentication)
  - [4.3 Successful RDP Access](#43-successful-rdp-access)
  - [4.4 System and Account Discovery](#44-system-and-account-discovery)
  - [4.5 PowerShell Execution-Policy Bypass](#45-powershell-execution-policy-bypass)
  - [4.6 Scheduled-Task Persistence](#46-scheduled-task-persistence)
  - [4.7 C2-Style HTTP Beacon](#47-c2-style-http-beacon)
  - [4.8 Controlled Outbound Data Transfer](#48-controlled-outbound-data-transfer)
- [5. Indicators and Artifacts](#5-indicators-and-artifacts)
- [6. Analyst Assessment](#6-analyst-assessment)
- [7. Response Recommendations](#7-response-recommendations)
- [8. Conclusion](#8-conclusion)

---

## 1. Executive Summary

On August 2, 2026, a controlled multi-stage attack was simulated from a Kali Linux host against a Windows endpoint.

The investigation confirmed:

```text
Network reconnaissance
→ failed RDP authentication
→ successful RDP access
→ system and account discovery
→ PowerShell execution-policy bypass
→ scheduled-task persistence
→ outbound HTTP C2-style beacon
→ controlled outbound data transfer
```

Splunk was used to correlate Windows authentication, Sysmon, PowerShell, and Suricata events into a single incident timeline.

The activity was authorized and used harmless lab files. In a production environment, the same sequence would warrant immediate containment and escalation.

---

## 2. Incident Scope

| Field | Value |
|---|---|
| Attacker | Kali Linux — `192.168.10.10` |
| Victim | Windows 10 — `DESKTOP-17JMLSF` — `192.168.20.20` |
| Target account | `victimuser` |
| Initial access method | RDP using a valid lab account after failed password attempts |
| Persistence method | Scheduled task launching PowerShell |
| C2-style destination | `192.168.10.10:8000` |
| Data-transfer destination | `192.168.10.10:9001` |

The repository README documents the lab architecture, system configuration, data sources, MITRE ATT&CK mapping, and reusable SPL queries. This report focuses only on the incident investigation and evidence.

---

## 3. Chronological Timeline

| Time | Stage | Key evidence |
|---|---|---|
| 14:58:10–14:58:19 | Network reconnaissance | Suricata recorded TCP flows from `192.168.10.10` to ports `135`, `139`, `445`, `3389`, and `5985` on `192.168.20.20` |
| 15:11:12 | Failed RDP login | Event ID `4625`; user `victimuser`; source `192.168.10.10`; bad password |
| 15:11:16 | Failed RDP login | Second Event ID `4625` from `192.168.10.10` |
| 15:11:18 | Failed RDP login | Third Event ID `4625` from `192.168.10.10` |
| 15:11:44 | Successful RDP access | Event ID `4624`; Logon Type `10`; user `victimuser`; source `192.168.10.10` |
| 15:31:39 | System and account discovery | Sysmon recorded PowerShell running `whoami`, `hostname`, `ipconfig`, `Get-LocalUser`, and `Get-Process` |
| 15:34:36 | PowerShell script execution | Event ID `4104` recorded `ExecutionPolicy Bypass` and `C:\SOC-LAB\stage3.ps1` |
| 15:35:44 | Scheduled-task persistence | Scheduled-task creation and execution commands were detected |
| 15:36:24 | C2-style HTTP beacon | Windows connected to `192.168.10.10:8000`; URI contained hostname, username, and `stage=complete` |
| 15:37:28 | Continued C2-style flow | Suricata recorded the corresponding HTTP/TCP flow |
| 15:44:06 | Controlled outbound data transfer | Windows sent `3,045` bytes to Kali over TCP port `9001`; Suricata recorded 6 outbound packets |

Repeated successful RDP Event ID `4624` records were also observed at 15:27:14 and 15:30:42, consistent with additional session activity or reconnections.

---

## 4. Evidence and Findings

### 4.1 Network Reconnaissance

Kali scanned selected Windows management, file-sharing, and remote-access ports. Suricata recorded flows to ports `135`, `139`, `445`, `3389`, and `5985`.

The activity is consistent with targeted network-service discovery.

<img width="975" height="550" alt="Splunk results showing Suricata reconnaissance flows" src="https://github.com/user-attachments/assets/e0ec6442-f899-4344-9659-7e29c4518c49" />

---

### 4.2 Failed RDP Authentication

Three failed authentication attempts were recorded for `victimuser` from `192.168.10.10`.

| Time | Event ID | Result |
|---|---:|---|
| 15:11:12.014 | 4625 | Bad password |
| 15:11:16.259 | 4625 | Bad password |
| 15:11:18.490 | 4625 | Bad password |

**Status:** `0xC000006D`  
**Sub-status:** `0xC000006A`

<img width="975" height="588" alt="Splunk results showing three failed RDP authentication events" src="https://github.com/user-attachments/assets/33d71be5-898b-45fd-b6e1-61e16acf31db" />

---

### 4.3 Successful RDP Access

A successful RemoteInteractive logon followed the failed attempts.

| Time | User | Source IP | Logon Type | Event ID |
|---|---|---|---:|---:|
| 15:11:44.420 | `victimuser` | `192.168.10.10` | 10 | 4624 |

Logon Type `10` is consistent with RDP access.

<img width="975" height="497" alt="Splunk results showing successful RDP Logon Type 10" src="https://github.com/user-attachments/assets/a5d58c9c-59ad-446a-a282-c021db047406" />

---

### 4.4 System and Account Discovery

PowerShell collected information about the victim system and user context.

Observed commands included:

- `whoami`
- `hostname`
- `ipconfig`
- `Get-LocalUser`
- `Get-Process`

This exposed the current user, hostname, network configuration, local accounts, and running processes.

<img width="975" height="403" alt="Splunk Sysmon results showing PowerShell discovery commands" src="https://github.com/user-attachments/assets/49c86a2f-c1e3-42bf-944a-ae1a99774d73" />

---

### 4.5 PowerShell Execution-Policy Bypass

PowerShell Event ID `4104` recorded execution of a harmless lab script using an execution-policy bypass.

| Time | Host | Event ID | Command |
|---|---|---:|---|
| 15:34:36.658 | `DESKTOP-17JMLSF` | 4104 | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\SOC-LAB\stage3.ps1"` |

The script was harmless, but `ExecutionPolicy Bypass` is a high-value detection indicator because it can be used to run scripts outside normal policy restrictions.

<img width="975" height="592" alt="Splunk results showing PowerShell execution-policy bypass" src="https://github.com/user-attachments/assets/296ae8cf-54a1-4edb-80e7-e70c2c541747" />

---

### 4.6 Scheduled-Task Persistence

PowerShell activity showed the creation and execution of a scheduled task.

| Time | Host | Detected actions |
|---|---|---|
| 15:35:44.596 | `DESKTOP-17JMLSF` | `New-ScheduledTaskAction` |
| 15:35:44.597 | `DESKTOP-17JMLSF` | `New-ScheduledTaskTrigger`, `Register-ScheduledTask`, `Start-ScheduledTask` |

In a production environment, an unexpected task launching PowerShell at logon should be treated as potential persistence.

<img width="975" height="506" alt="Splunk results showing scheduled-task persistence commands" src="https://github.com/user-attachments/assets/daef9d9b-b1e7-4d35-a15b-c731e0137cee" />

---

### 4.7 C2-Style HTTP Beacon

The Windows victim initiated an outbound HTTP connection to a Kali-controlled listener.

| Time | Source | Destination | Protocol | URI |
|---|---|---|---|---|
| 15:36:24.453 | `192.168.20.20` | `192.168.10.10:8000` | HTTP/TCP | `/?host=DESKTOP-17JMLSF&user=victimuser&stage=complete` |
| 15:37:28.231 | `192.168.20.20` | `192.168.10.10:8000` | HTTP/TCP | Continued flow |

This was a controlled beacon simulation, not actual malware command-and-control activity.

<img width="975" height="443" alt="Splunk Suricata results showing the simulated HTTP beacon" src="https://github.com/user-attachments/assets/e95bf0bd-dd34-43ea-8693-ff5c8ad605c5" />

---

### 4.8 Controlled Outbound Data Transfer

Suricata recorded an outbound TCP connection from the Windows victim to the Kali system on port `9001`.

| Time | Source | Destination | Protocol | Packets Sent | Bytes Sent | Bytes Received | Total Bytes |
|---|---|---|---|---:|---:|---:|---:|
| 15:44:06.953 | `192.168.20.20:61004` | `192.168.10.10:9001` | TCP | 6 | 3,045 | 186 | 3,231 |

The flow confirms that data moved from the Windows victim to the Kali-controlled listener. Suricata flow metadata does not identify the exact file contents, so the event is documented as a **controlled outbound data transfer / simulated exfiltration**.

<img width="975" height="481" alt="image" src="https://github.com/user-attachments/assets/830b5b8a-edd8-426c-b0a3-7cd5aea89a67" />


---

## 5. Indicators and Artifacts

| Type | Indicator |
|---|---|
| Attacker IP | `192.168.10.10` |
| Victim IP | `192.168.20.20` |
| Victim hostname | `DESKTOP-17JMLSF` |
| Target account | `victimuser` |
| Reconnaissance ports | `135`, `139`, `445`, `3389`, `5985` |
| Beacon destination | `192.168.10.10:8000` |
| Data-transfer destination | `192.168.10.10:9001` |
| PowerShell script | `C:\SOC-LAB\stage3.ps1` |
| Scheduled task | `SOC-LAB-Update` |
| Beacon marker | `stage=complete` |
| Outbound source port | `61004` |
| Confirmed outbound bytes | `3,045` |

---

## 6. Analyst Assessment

### What happened

A Kali host enumerated services on a Windows endpoint. Repeated RDP login failures were followed by successful RDP access using the lab account `victimuser`.

After access, PowerShell was used for system and account discovery. A harmless script was executed with an execution-policy bypass, and a scheduled task was created to simulate persistence.

The Windows victim then sent a C2-style HTTP beacon to Kali and later transferred `3,045` bytes over TCP port `9001`.

### Why it matters

The combination of failed authentication, successful remote access, suspicious PowerShell activity, persistence, beaconing, and outbound data movement forms a coherent attack pattern.

In a production environment, this sequence would indicate a potentially compromised endpoint and would require immediate containment.

### Confidence

**High.** The activity was validated across independent endpoint and network evidence:

- Windows Security events for RDP authentication
- Sysmon process-creation events
- PowerShell Script Block Logging
- Suricata network-flow and HTTP metadata
- Splunk correlation and timeline reconstruction

---

## 7. Response Recommendations

For an equivalent production incident:

1. Isolate the affected endpoint.
2. Disable or reset the affected user account.
3. Terminate unauthorized RDP sessions.
4. Block the attacker, beacon, and data-transfer destinations.
5. Remove unauthorized scheduled tasks.
6. Quarantine suspicious scripts and archives.
7. Review related authentication, EDR, PowerShell, DNS, proxy, firewall, and network-flow logs.
8. Search other systems for matching indicators and commands.
9. Rotate credentials used on the affected endpoint.
10. Preserve forensic evidence before remediation.
11. Require MFA and restrict RDP to approved management networks.
12. Create correlation alerts for repeated `4625` failures followed by a `4624` Logon Type `10`.
13. Alert on PowerShell execution-policy bypass, scheduled-task creation, unusual HTTP destinations, and outbound transfers to uncommon ports.

---

## 8. Conclusion

The investigation reconstructed a complete controlled attack sequence using endpoint and network telemetry:

```text
Reconnaissance
→ failed RDP attempts
→ successful RDP access
→ discovery
→ PowerShell execution
→ scheduled-task persistence
→ C2-style HTTP beacon
→ controlled outbound data transfer
```

The lab demonstrates the ability to identify suspicious activity, correlate multiple log sources, reconstruct a timeline, assess impact, and recommend containment actions.

Detailed lab architecture, reusable SPL searches, MITRE ATT&CK mapping, and setup information remain in the project README to avoid duplicating content in this incident report.
