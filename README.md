# Incident-Response-Analysis-Apex-Financials-Spring-2025

# 🛡️ Incident Response Analysis – Apex Financials (Spring 2025)

This repository presents a two-phase cybersecurity investigation conducted on simulated attacks at Apex Financials as part of the graduate program in Digital Forensics & Cybersecurity at the University at Albany, SUNY. The project involved comprehensive incident response and forensic analysis using professional-grade tools and real-world threat modeling.

---

## 📘 Overview of the Incidents

### 🔐 Incident 1 – Spear-Phishing & Ransomware Deployment (Case ID: INC250306)

A carefully crafted phishing email targeting an internal analyst led to a macro-based payload execution. This event triggered a chain of credential compromise and lateral movement activities, culminating in the deployment of the **ShadowCrypt ransomware** on an internal asset.

- Entry Method: Malicious PDF attachment  
- Targeted Host: WORKSTATION-01 (`apexfinancial\analyst1`)  
- Attack Flow:
  - Macro execution via `Q1 Performance Review.pdf` (MITRE: T1204.002)
  - Pass-the-hash attack and brute-force login (T1110, T1550.002)
  - Lateral movement via PsExec and WMI
  - Scheduled tasks (T1053.005) ensured persistence
- Indicators of Compromise:
  - C2 IP: `185.143.223.47`
  - System registry modifications
- Impact Summary: Potential theft of intellectual property, encryption of financial records, and operational shutdown

---

### 🌐 Incident 2 – Web Server Exploitation & Data Exfiltration (Case ID: INC250422)

The second incident involved unauthorized access to a web portal followed by exploitation of file upload vulnerabilities. Attackers gained persistent control via PHP web shells and conducted exfiltration of sensitive organizational data.

- Initial Vector: Brute-force login to `/login.php`  
- Exploitation Steps:
  - SQL Injection
  - Upload of `c99shell.php` and `eval-stdin.php`
  - Remote command execution (`cmd=whoami`, `cmd=ls`)
- Data Breach:
  - ~50GB of data exfiltrated to `167.172.3.114`
  - Leaked assets: `db_config.php`, `backup.tar.gz`, `.csv/.xls` files
- **Log Files Reviewed**:
  - `access.log`, `IDS_logs.txt`, `FW_logs.txt`
- MITRE Tactics Used:
  - T1110 – Brute Force
  - T1505.003 – Web Shell
  - T1059.003 – PHP Execution
  - T1041 – Exfiltration over HTTP

---

## 🔧 Tools & Techniques Utilized

- Splunk – Log correlation and timeline construction  
- Wireshark & Security Onion – Network telemetry and detection  
- Firewall/IDS Logs – Log evidence of attack paths and response  
- YARA, Wazuh, ClamAV, Sysmon – Detection rules and behavioral monitoring (simulated)  
- Linux CLI & PowerShell – System interrogation, log preservation

---

## 📂 Repository Contents

| File Name                               | Description                                                        |
|----------------------------------------|--------------------------------------------------------------------|
| INC250306_5689_Group1_Report_Part1.pdf | Part 1: Report on spear-phishing & ransomware attack               |
| Project_Part1_Resource_INC250306_5689.pdf | Part 1: Scope, task, and project outline                           |
| INC40122_5689_Group_1_Report_Part2.pdf | Part 2: Report on web shell exploitation and data exfiltration     |
| Project_Part2_Resource.pdf             | Part 2: System diagram, asset roles, and infrastructure overview   |
| Project_Part2_Resource_INC250422.pptx  | Part 2: Logs and attack hints (PowerPoint)                         |
| Project_Part2_Resource_readme.txt      | Part 2: XOR clue and project identifiers                           |
| Project_Presentation_Report2.pdf       | Final team presentation summarizing key findings                  |

---

## 🧠 Key Takeaways

- Spear-phishing defense requires modern email filtering and regular user training  
- Input validation, WAFs, and hardened PHP configs are essential for web app security  
- MFA and endpoint visibility help reduce lateral movement risk  
- A proactive forensic strategy (disk imaging, log hashing) improves response capabilities

---

## 👥 Contributors

- Sriram Rayala  
- Leela Pavan  
- Shalem Raju  
- SriVarsha Adla  
- Junaid Mohammed  
- Phanindhar Reddy Kommalapati  

Master’s in Cybersecurity & Digital Forensics  
University at Albany, SUNY – Spring 2025

---

## 📄 License

This project is licensed under the  
Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0)

> You may view and share this content with proper attribution.  
> However, modification and commercial use are not permitted.

[🔗 View License Terms](https://creativecommons.org/licenses/by-nc-nd/4.0/)
