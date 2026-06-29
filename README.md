# Microsoft Sentinel SIEM: Threat Detection & Incident Response Lab

## (Advanced Tor Infiltration & Configuration Deletion Simulation)

## Project Overview

This project demonstrates the end-to-end deployment of a Cloud-Native SIEM using Microsoft Sentinel to architect a fully operational Security Operations Center (SOC) environment. Moving beyond baseline monitoring, this lab features a hands-on advanced attack simulation where a test user account was infiltrated via the Tor Anonymizing Network to execute malicious administrative actions, specifically unauthorized configuration deletions. The entire incident lifecycle—from ingestion and custom KQL alerts to deep graph investigation and final PDF report remediation—was executed and documented.

## Key Features & Lab Milestones

- **Cloud SIEM & Data Ingestion:** Provisioned Microsoft Sentinel over a centralized Azure Log Analytics Workspace (SEC-Monitoring) to collect platform, identity, and security logs.

- **Threat Intel & Behavioral Analytics (UEBA):** Configured User and Entity Behavior Analytics to track anomalous access footprints across cloud directory assets.

- **Advanced Attack Simulation (Tor & Data Destruction):**
  - Utilized the Tor Browser to route traffic through foreign exit nodes, simulating an obfuscated external threat actor utilizing compromised credentials.
  - Executed malicious post-exploitation activity by deleting critical directory/resource configurations to simulate service disruption and data destruction.

- **Custom KQL Analytics Rules:** Authored targeted scheduled query rules using Kusto Query Language (KQL) to trigger high-severity incidents upon detecting signs of anonymized routing or unexpected administrative deletions.

- **SOC Triage & Incident Graph Investigation:** Conducted full triage using Sentinel's Investigation Graph to analyze the blast radius, linking the compromised test user entity, the malicious Tor exit node IP, and the tampered configuration assets.

- **Remediation & Reporting:** Contained the threat by revoking active user tokens, restoring secure baselines, and exporting an official executive SOC Incident Report PDF for audit compliance.

## Technologies & Tools Used

| Category | Tool / Service |
|---|---|
| SIEM Platform | Microsoft Sentinel |
| Log Management | Log Analytics Workspace (LAW) |
| Identity & Access Management | Microsoft Entra ID (Azure AD) |
| Attack Infrastructure | Tor Browser Network (Anonymizing Exit Nodes) |
| Query Language | Kusto Query Language (KQL) |
| Framework Mapping | MITRE ATT&CK (T1485, T1105) |

---

## Technical Architecture & Simulation Steps

### Phase 1: Ingestion & Sentinel Setup

1. Deployed an Azure Log Analytics Workspace named **SEC-Monitoring** and enabled the Microsoft Sentinel solution on top of it.
2. Enabled diagnostic settings across identity providers to pipe SigninLogs and AuditLogs directly into the SIEM pipeline.

### Phase 2: Writing the KQL Detection Rules

To catch the specific attack pattern simulated, custom KQL rules were implemented.

**Rule 1 — Tor Exit Node Sign-In Detection:**
```kql
let TorNodes = (_GetWatchlist('Tor-IP-Address') | project TorIP = IpAddress);
SigninLogs
| where IPAddress in (TorNodes)
| where ResultType != 50126
| project
    TimeGenerated,
    Location,
    IPAddress,
    UserDisplayName,
    UserPrincipalName,
    UserId,
    LocationDetails,
    RiskState,
    RiskLevelDuringSignIn,
    AuthenticationRequirement,
    ClientAppUsed,
    ConditionalAccessAudiences
```

**Rule 2 — Unauthorized Configuration Deletion Detection:**
```kql
AuditLogs
| where OperationName has_any ("Delete", "Remove")
| where Result == "success"
| where InitiatedBy.user.userPrincipalName != ""
| project
    TimeGenerated,
    OperationName,
    Result,
    InitiatedBy,
    TargetResources,
    AdditionalDetails
```

### Phase 3: Attack Simulation

1. Launched the **Tor Browser** and connected through a foreign exit node to mask the origin IP.
2. Used compromised test-user credentials to authenticate into the Azure portal through the anonymized connection.
3. Executed unauthorized **deletion of directory/resource configurations**, simulating a destructive insider/external threat scenario.

### Phase 4: Incident Triage & Graph Investigation

1. Sentinel triggered **High-Severity incidents** based on the custom KQL analytics rules.
2. Used the **Sentinel Investigation Graph** to visually map the attack chain.
3. Analyzed the **blast radius** and identified all affected resources.

### Phase 5: Remediation & Reporting

1. **Revoked active sessions** and refresh tokens for the compromised user account via Microsoft Entra ID.
2. **Restored secure baseline configurations** to remediate the impact of the deletions.
3. Exported an official **SOC Incident Report PDF** for audit trail and compliance documentation.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Impact | Data Destruction | T1485 |
| Command & Control | Ingress Tool Transfer | T1105 |
| Defense Evasion | Use of Anonymizing Proxy (Tor) | T1090.003 |

---

## Repository Structure

```
├── README.md
├── detection-rules/
│   └── custom_detection_rule.kql
├── watchlists/
│   └── high_risk_users.csv
└── screenshots/
    ├── sentinel_dashboard.png
    ├── incident_graph.png
    └── remediation_success.pdf
```

---

## Screenshots

> Screenshots and the final remediation PDF report are located in the /screenshots directory.

---

*Built by [Kuldeep Mishra](https://github.com/Kuldeep-Mishra00) | SOC Lab Project | Microsoft Sentinel*
