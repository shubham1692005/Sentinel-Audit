# 🛡️ Sentinel Audit
### Cyber Risk Assessment & Security Assurance Platform

**Identify security risks. Assess vulnerabilities. Strengthen security posture.**

Sentinel Audit is a Python-based cybersecurity assessment platform designed to support asset inventory, system and network assessment workflows, vulnerability analysis, risk management, and audit reporting through a unified web interface.

[**View the GitHub Repository**](https://github.com/shubham1692005/Sentinel-Audit)

> **Project status:** Development / Demonstration. This repository contains the project source code and setup configuration; it is not a hosted live service.

---

## 📸 Application Screenshots

### Security Dashboard

An overview of inventoried assets, assessments, open findings, and assessment coverage.

![Sentinel Audit dashboard](screenshots/overview.png)

### Assessment History

Shows assessment activity, completion status, scan scope, and saved assessment records. The example shown has zero recorded findings and notes that some host checks could not collect data.

![Sentinel Audit assessment history](screenshots/assessments.png)

### Risk Register & Findings

A workspace for reviewing assessment findings, searching CVEs, filtering by severity and status, and accessing reports. The example shown contains no recorded findings.

![Sentinel Audit findings](screenshots/findings.png)

---

## 🚀 Key Features

- **Asset Management:** Maintain an inventory of assessed assets.
- **Security Assessments:** Run supported local-system and network assessment workflows.
- **Network Scanning:** Integrate Nmap for network discovery and service detection.
- **Vulnerability Analysis:** Support service and vulnerability correlation with CVE/CVSS information.
- **Risk Management:** Review findings and track remediation status.
- **Compliance Workflows:** Provide governance- and compliance-related functionality.
- **Assessment History:** Retain records of completed assessments.
- **Reporting:** Export assessment information in PDF and JSON formats.
- **User Management:** Manage user accounts and access roles.
- **Android Integration:** Include Android device assessment capabilities.

*Feature availability and assessment coverage depend on configuration, permissions, operating system, and installed tools.*

---

## 🧰 Technology Stack

| Area | Technology |
|---|---|
| Backend | Python |
| Frontend | HTML, CSS, JavaScript |
| Network scanning | Nmap |
| Vulnerability intelligence | CVE / CVSS correlation |
| Database | SQLite |
| Mobile application | Android / Java |
| Reporting | PDF / JSON |
| Deployment configuration | Docker / Firebase |

---

## 📂 Project Structure

```text
Sentinel-Audit/
├── android/                  # Android application
├── security_audit/
│   ├── security_audit/       # Python backend
│   └── web/                  # Web interface
├── web/                      # Frontend assets
├── tests/                    # Test suite
├── screenshots/              # README screenshots
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── firebase.json
├── firestore.rules
├── run.bat
├── .env.example
└── README.md
```

---

## ⚙️ Installation & Setup

### Prerequisites

- Python 3
- Git
- Nmap
- A compatible Windows or Linux environment

### 1. Clone the repository

```bash
git clone https://github.com/shubham1692005/Sentinel-Audit.git
cd Sentinel-Audit
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment variables

Review `.env.example` and configure the variables required by your environment. Do not commit your real `.env` file, passwords, API secrets, private keys, or service-account credentials.

### 4. Run on Windows

```cmd
run.bat
```

Follow the startup instructions printed in the terminal. Refer to the deployment documentation for additional configuration.

---

## 🔐 Security & Responsible Use

Sentinel Audit is intended for authorised security assessments.

- Assess only systems you own or have explicit permission to test.
- Confirm the assessment scope before running scans.
- Treat vulnerability matches as candidates until validated.
- Protect assessment reports and sensitive asset information.
- Secure authentication, access controls, and deployment credentials.
- Do not expose production services or dashboards without appropriate security configuration.

---

## ⚠️ Project Status & Limitations

Sentinel Audit is an evolving development/demo project and should not be considered a fully validated production security platform.

Assessment coverage depends on operating-system capabilities, user permissions, available tools, and collected evidence. Some checks may return incomplete results. The screenshots are examples of the current interface; the displayed assessment has zero findings, and one screen reports incomplete host-check collection. They should not be interpreted as proof that a system is vulnerability-free.

Potential vulnerability matches require verification before remediation decisions are made.

---

## 🛣️ Future Improvements

- Improve assessment coverage and evidence collection.
- Enhance vulnerability validation and risk scoring.
- Expand compliance framework mappings.
- Strengthen authentication and access controls.
- Improve audit evidence and reporting.
- Explore AI-assisted security risk analysis and governance workflows.
- Expand automated testing and deployment validation.

---

## 👨‍💻 Author

**Shubham Modi**  
Cybersecurity · GRC · Risk Management · AI Governance

**Repository:** [github.com/shubham1692005/Sentinel-Audit](https://github.com/shubham1692005/Sentinel-Audit)

---

*Built as a practical cybersecurity project focused on security assessment, risk visibility, and governance-oriented workflows.*
