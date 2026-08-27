# CyberShield Nexus
### NEDI AI Cyber Command Center - Academic Cybersecurity Demo

CyberShield Nexus is a Spring Boot cybersecurity operations prototype built around a fictional scenario: **NEDI - National Education Digital Infrastructure**. NEDI represents an education technology environment that centrally monitors digital services such as student portals, faculty portals, examination systems, ERP, admissions, digital library, LMS, and mail services across many institutions.

NEDI is a fictional scenario created for this academic cybersecurity demo. No real organization or government body owns or operates this system.

![Java](https://img.shields.io/badge/Java-21-orange?style=flat-square)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.5-green?style=flat-square)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue?style=flat-square)
![OWASP](https://img.shields.io/badge/OWASP-A01%20A02%20A07%20A09-red?style=flat-square)

---

## Scenario

NEDI manages critical education services:

- Student Portal
- Faculty Portal
- Examination Portal
- ERP
- Admission Portal
- Email Services
- Digital Library
- Learning Management System

Each service depends on servers, firewalls, routers/switches, databases, licenses, and hardware. CyberShield Nexus acts as the central SOC-style command center that receives safe simulated telemetry, calculates risk, creates incidents, and helps administrators respond.

---

## Quick Start

```bash
# 1. Start PostgreSQL and create the database
#    Database: cybershield_db
#    User: cybershield_user
#    Password: CyberShield@2024

# 2. Run the application
cd cybershield-nexus
mvn spring-boot:run

# 3. Open browser
http://localhost:8081/index.html

# 4. Login
Username: admin        Password: Admin@123
Username: serveradmin  Password: Admin@123
Username: viewer       Password: Admin@123
```

---

## Frontend Pages

| Page | URL |
|------|-----|
| NEDI Home | `http://localhost:8081/index.html` |
| Login | `http://localhost:8081/login.html` |
| Dashboard | `http://localhost:8081/dashboard.html` |
| Servers | `http://localhost:8081/servers.html` |
| Firewalls | `http://localhost:8081/firewalls.html` |
| Licenses | `http://localhost:8081/licenses.html` |
| Hardware | `http://localhost:8081/hardware.html` |
| Incidents | `http://localhost:8081/incidents.html` |
| Risk & BFS | `http://localhost:8081/risk.html` |
| Audit Log | `http://localhost:8081/audit-log.html` |

---

## How The Demo Works

1. Open the NEDI home page and explain that the organization is fictional.
2. Login using one of the seeded accounts.
3. Show the dashboard, asset inventory, incidents, risk page, and audit log.
4. Run safe simulated attack scripts to generate security events.
5. Watch audit logs, account lockout, risk score, and incidents update.
6. Use the BFS attack-path endpoint/page to explain possible lateral movement.
7. Mark incidents as investigating or resolved from the incident workflow.

---

## Run Attack Scripts

```bash
cd attack-scripts

# Run all 3 safe simulations in sequence
python run_all_attacks.py

# Or run individually:
python brute_force.py   # OWASP A07 - Identification and Authentication Failures
python idor_test.py     # OWASP A01 - Broken Access Control
python tamper_jwt.py    # OWASP A02 - Cryptographic Failures
```

These scripts are for controlled local demonstration only.

---

## Risk Engine Formula

```text
Risk Score (0-100) =
  +30  if server is not patched in 90 days
  +25  if a linked license is expired
  +20  if repeated LOGIN_FAIL events appear in the audit log
  +15  if reachable from a low-trust graph node

Score 50+  -> auto-create LOW incident
Score 70+  -> auto-create MEDIUM incident
Score 85+  -> auto-create HIGH incident
Score 95+  -> auto-create CRITICAL incident
```

The current engine is rule-based. In later phases, the project should label recommendations as **AI-assisted** and generate them from the actual risk breakdown.

---

## BFS Attack Path

```text
Seeded graph example:
USER:3 -> FIREWALL:1 -> SERVER:1 -> SERVER:2 -> SERVER:3

API:
GET /api/graph/attack-path?startId=3&startType=USER&targetId=3&targetType=SERVER
```

This demonstrates how CyberShield Nexus can identify a shortest path from a compromised user or low-trust entry point to a critical server.

---

## OWASP Coverage

| ID | Name | Demo | Protection |
|----|------|------|------------|
| A01 | Broken Access Control | `idor_test.py` | `@PreAuthorize` role checks and protected write operations |
| A02 | Cryptographic Failures | `tamper_jwt.py` | HMAC-SHA384 JWT signature validation |
| A07 | Identification and Authentication Failures | `brute_force.py` | Account lockout, audit logging, auto incident creation |
| A09 | Security Logging and Monitoring Failures | Audit Log page | Login and API activity stored with user/IP/timestamp context |

---

## Project Structure

```text
cybershield-nexus/
├── src/main/java/com/cybershield/
│   ├── config/          # Security, web config, data seeders
│   ├── controller/      # REST controllers
│   ├── model/           # JPA entities
│   ├── repository/      # Spring Data repositories
│   ├── service/         # Business logic services
│   └── security/        # JWT filter and token provider
├── src/main/resources/static/
│   ├── css/style.css
│   ├── js/auth.js
│   ├── index.html
│   ├── login.html
│   ├── dashboard.html
│   ├── servers.html
│   ├── firewalls.html
│   ├── licenses.html
│   ├── hardware.html
│   ├── incidents.html
│   ├── risk.html
│   └── audit-log.html
├── attack-scripts/
│   ├── brute_force.py
│   ├── idor_test.py
│   ├── tamper_jwt.py
│   ├── run_all_attacks.py
│   └── CyberShield_Postman_Collection.json
└── PROJECT_REPORT.html
```

---

## Tech Stack

- Java 21 and Spring Boot 3.2.5
- Spring Security and JWT
- PostgreSQL and Hibernate/JPA
- BCrypt password hashing
- BFS algorithm for attack-path traversal
- Vanilla HTML/CSS/JavaScript frontend

---

## Phase 1 Status — ✅ Complete

Project identity is clean. CyberShield Nexus is the product name. NEDI (National Education Digital Infrastructure) is the fictional scenario. All AICTE/PYHack02 references have been removed from frontend, backend comments, seed data, attack scripts, and the project report. The scenario is clearly presented as fictional and safe for academic demonstration.

Phase 2 onwards: Backend NEDI models (Institution, DigitalService), richer seed data, AI-assisted recommendations, SOC dashboard redesign, incident workflow, report generation, and tests.
