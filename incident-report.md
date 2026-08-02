# SOC Incident Report  
## August 2, 2026 — Reconnaissance-to-C2 Investigation

**Environment:** Isolated VirtualBox Home Lab  
**Report Date:** August 2, 2026  
**Analyst:** Nehal Patel  
**Classification:** Controlled Security Simulation  

---

## 1. Executive Summary

On August 2, 2026, a controlled multi-stage intrusion was simulated against a Windows victim from a Kali Linux attacker inside an isolated VirtualBox home lab.

Traffic was routed through an Ubuntu SOC gateway running Suricata, Wireshark, tcpdump, and Splunk Enterprise. Endpoint telemetry from Windows Security, Sysmon, PowerShell, Defender, System, and Application logs was forwarded to Splunk.

The investigation confirmed:

- Targeted network reconnaissance
- PowerShell-based system and account discovery
- PowerShell execution-policy bypass
- Script execution
- Scheduled-task persistence
- An outbound HTTP C2-style beacon

This was a harmless training exercise. No real malware or unauthorized external system was involved.

---

## 2. Systems in Scope

| Role | Host | IP Address |
|---|---|---|
| Attacker | Kali Linux | `192.168.10.10` |
| SOC gateway | Ubuntu SOC | `192.168.10.1` / `192.168.20.1` |
| Victim | `DESKTOP-17JMLSF` | `192.168.20.20` |

### Evidence Sources

- Suricata `eve.json`
- Sysmon Operational
- PowerShell Operational
- Splunk Enterprise
- Wireshark and tcpdump validation

---

## 3. Severity

**Production severity:** High  
**Lab classification:** Controlled simulation

The combination of reconnaissance, PowerShell execution-policy bypass, persistence, and outbound beaconing would require immediate escalation and containment in a production environment.

---

## 4. Incident Timeline — August 2, 2026

| Time | Stage | Evidence |
|---|---|---|
| 14:58:10–14:58:19 | Network reconnaissance | Kali `192.168.10.10` generated TCP flows to Windows `192.168.20.20` on ports `135`, `139`, `445`, `3389`, and `5985` |
| 15:31:39 | System and account discovery | PowerShell executed `whoami`, `hostname`, `ipconfig`, `Get-LocalUser`, and `Get-Process` |
| 15:34:36 | PowerShell payload execution | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\SOC-LAB\stage3.ps1"` recorded in PowerShell Event ID `4104` |
| 15:35:44 | Scheduled-task persistence | `New-ScheduledTaskAction`, `New-ScheduledTaskTrigger`, `Register-ScheduledTask`, and `Start-ScheduledTask` detected |
| 15:36:24 | C2-style HTTP beacon | Windows `192.168.20.20` connected to Kali `192.168.10.10:8000` over HTTP |
| 15:36:24 | Beacon details | URI contained `host=DESKTOP-17JMLSF`, `user=victimuser`, and `stage=complete` |
| 15:37:28 | Confirmed outbound flow | Suricata recorded the continuing HTTP/TCP flow from Windows to Kali |

---

## 5. Detailed Findings

### 5.1 Network Reconnaissance

Suricata recorded repeated TCP flows from the Kali attacker to selected Windows administrative and remote-access ports.

| Port | Likely Service |
|---|---|
| 135 | Microsoft RPC |
| 139 | NetBIOS Session Service |
| 445 | SMB |
| 3389 | Remote Desktop Protocol |
| 5985 | Windows Remote Management |

**Source:** `192.168.10.10`  
**Destination:** `192.168.20.20`

The activity is consistent with targeted service discovery.

---

### 5.2 System and Account Discovery

PowerShell was used to collect information from the victim system.

Observed commands:

- `whoami`
- `hostname`
- `ipconfig`
- `Get-LocalUser`
- `Get-Process`

These commands exposed the current user, hostname, network configuration, local accounts, and running processes.

---

### 5.3 Suspicious PowerShell Execution

PowerShell Event ID `4104` recorded:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\SOC-LAB\stage3.ps1"
```

The script was harmless, but the use of `ExecutionPolicy Bypass` is suspicious because it can allow scripts to run outside normal policy restrictions.

---

### 5.4 Scheduled-Task Persistence

The following PowerShell actions were detected:

- `New-ScheduledTaskAction`
- `New-ScheduledTaskTrigger`
- `Register-ScheduledTask`
- `Start-ScheduledTask`

The task was created as a persistence simulation. In a production environment, a newly registered task launching PowerShell would require immediate investigation.

---

### 5.5 C2-Style HTTP Beacon

The Windows victim initiated an outbound HTTP connection to the Kali server.

| Field | Value |
|---|---|
| Source IP | `192.168.20.20` |
| Destination IP | `192.168.10.10` |
| Destination port | `8000` |
| Protocol | HTTP over TCP |
| URI | `/?host=DESKTOP-17JMLSF&user=victimuser&stage=complete` |

The request transmitted the victim hostname, username, and completion status.

This was a **C2-style simulation only**, not an actual malware command-and-control channel.

---

## 6. Attack-Chain Summary

```text
Network reconnaissance
        ↓
System and account discovery
        ↓
PowerShell execution-policy bypass
        ↓
PowerShell script execution
        ↓
Scheduled-task persistence
        ↓
Outbound HTTP C2-style beacon
```

> RDP authentication events from July 28 were intentionally excluded from this report. No August 2 RDP authentication evidence was included in the supplied dataset.

---

## 7. Indicators of Compromise

| Type | Indicator |
|---|---|
| Attacker IP | `192.168.10.10` |
| Victim IP | `192.168.20.20` |
| Victim hostname | `DESKTOP-17JMLSF` |
| User | `victimuser` |
| Scanned ports | `135`, `139`, `445`, `3389`, `5985` |
| Beacon destination | `192.168.10.10:8000` |
| Script path | `C:\SOC-LAB\stage3.ps1` |
| Scheduled task | `SOC-LAB-Update` |
| Beacon marker | `stage=complete` |

---

## 8. MITRE ATT&CK Mapping

| Activity | MITRE ATT&CK Technique |
|---|---|
| Port and service discovery | Network Service Scanning |
| User discovery | Account Discovery |
| Hostname discovery | System Name Discovery |
| Network discovery | System Network Configuration Discovery |
| Process discovery | Process Discovery |
| PowerShell execution | Command and Scripting Interpreter: PowerShell |
| Scheduled-task persistence | Scheduled Task/Job |
| HTTP beacon | Application Layer Protocol: Web Protocols |

---

## 9. Containment Recommendations

In a production environment:

1. Isolate the affected endpoint.
2. Block the suspicious source and destination IPs.
3. Terminate unauthorized remote sessions.
4. Remove unauthorized scheduled tasks.
5. Quarantine suspicious scripts and related files.
6. Review Sysmon, PowerShell, Security, Defender, and network logs.
7. Reset potentially affected credentials.
8. Restrict RDP and administrative services to approved networks.
9. Alert on execution-policy bypass.
10. Alert on unusual outbound HTTP traffic to non-standard ports.

---

## 10. Remediation Recommendations

- Enforce MFA for remote access.
- Restrict administrative ports through firewall rules.
- Enable PowerShell Script Block Logging.
- Maintain Sysmon process and network telemetry.
- Monitor scheduled-task creation.
- Alert on suspicious PowerShell command lines.
- Alert on unusual outbound HTTP connections.
- Segment attacker, user, and management networks.
- Retain centralized logs in Splunk for correlation and investigation.

---

## 11. Conclusion

The August 2 investigation successfully correlated network and endpoint evidence across Suricata, Sysmon, PowerShell, and Splunk.

The confirmed sequence was:

```text
Reconnaissance
→ discovery
→ PowerShell execution
→ scheduled-task persistence
→ outbound HTTP C2-style beacon
```

The exercise demonstrated an end-to-end SOC workflow:

```text
Attack simulation
→ telemetry generation
→ centralized logging
→ detection
→ correlation
→ timeline reconstruction
→ MITRE ATT&CK mapping
→ containment recommendations
```
