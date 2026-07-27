# 🛡️ CyberShield Nexus
### AICTE PYHack02 — AI-Powered Data Center Intelligence & Security Portal

![Java](https://img.shields.io/badge/Java-21-orange?style=flat-square)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.5-green?style=flat-square)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue?style=flat-square)
![OWASP](https://img.shields.io/badge/OWASP-A01%20A02%20A07%20A09-red?style=flat-square)

---

## 🚀 Quick Start

```bash
# 1. Start PostgreSQL and create database
#    Database: cybershield_db  User: postgres

# 2. Run the application
cd cybershield-nexus
mvn spring-boot:run

# 3. Open browser
http://localhost:8081/login.html

# 4. Login
Username: admin     Password: Admin@123
Username: serveradmin  Password: Admin@123
Username: viewer    Password: Admin@123
```

---

## 🌐 Frontend Pages

| Page | URL |
|------|-----|
| 🔐 Login | `http://localhost:8081/login.html` |
| 📊 Dashboard | `http://localhost:8081/dashboard.html` |
| 🖥️ Servers | `http://localhost:8081/servers.html` |
| 🔥 Firewalls | `http://localhost:8081/firewalls.html` |
| 📋 Licenses | `http://localhost:8081/licenses.html` |
| ⚙️ Hardware | `http://localhost:8081/hardware.html` |
| 🚨 Incidents | `http://localhost:8081/incidents.html` |
| 📈 Risk & BFS | `http://localhost:8081/risk.html` |
| 📜 Audit Log | `http://localhost:8081/audit-log.html` |

---

## ⚔️ Run Attack Scripts

```bash
cd attack-scripts

# Run all 3 attacks in sequence
python run_all_attacks.py

# Or individually:
python brute_force.py   # OWASP A07 — Authentication Failures
python idor_test.py     # OWASP A01 — Broken Access Control
python tamper_jwt.py    # OWASP A02 — Cryptographic Failures
```

---

## 🧮 Risk Engine Formula

```
Risk Score (0-100) =
  +30  if server NOT patched in 90 days
  +25  if any linked license is EXPIRED
  +20  if ≥5 LOGIN_FAIL events in last 24h
  +15  if reachable from low-trust graph node
  +10  if linked hardware warranty expired

Score 50+  → AUTO-CREATE incident (LOW)
Score 70+  → AUTO-CREATE incident (MEDIUM)
Score 85+  → AUTO-CREATE incident (HIGH)
Score 95+  → AUTO-CREATE incident (CRITICAL)
```

---

## 🕸️ BFS Attack Path

```
Seeded Graph (15 edges):
USER:3 → FIREWALL:1 → SERVER:1 → SERVER:2 → SERVER:3 (DB)

API:
GET /api/graph/attack-path?startId=3&startType=USER&targetId=3&targetType=SERVER
→ { "found": true, "hops": 4, "path": ["USER:3","FIREWALL:1","SERVER:1","SERVER:2","SERVER:3"] }
```

---

## 🔐 OWASP Coverage

| ID | Name | Demo | Protection |
|----|------|------|-----------|
| A01 | Broken Access Control | `idor_test.py` | @PreAuthorize RBAC, 403 on all VIEWER writes |
| A02 | Cryptographic Failures | `tamper_jwt.py` | HMAC-SHA384 JWT, forged token → 401 |
| A07 | Authentication Failures | `brute_force.py` | Lockout after 5 fails, auto-incident |
| A09 | Security Logging | Audit Log page | 100% event coverage with IP + timestamp |

---

## 📁 Project Structure

```
cybershield-nexus/
├── src/main/java/com/cybershield/
│   ├── config/          # Security, Web, DataSeeder, JPA
│   ├── controller/      # 10 REST controllers
│   ├── model/           # 8 JPA entities
│   ├── repository/      # 8 Spring Data repositories
│   ├── service/         # 12 business logic services
│   └── security/        # JWT filter + token provider
├── src/main/resources/static/
│   ├── css/style.css    # Full dark theme design system
│   ├── js/auth.js       # JWT + API helpers
│   ├── login.html       # Login page
│   ├── dashboard.html   # Main dashboard
│   ├── servers.html     # Server CRUD
│   ├── firewalls.html   # Firewall CRUD
│   ├── licenses.html    # License CRUD
│   ├── hardware.html    # Hardware CRUD
│   ├── incidents.html   # Incident management
│   ├── risk.html        # Risk engine + BFS tool
│   └── audit-log.html   # Audit log viewer
├── attack-scripts/
│   ├── brute_force.py   # OWASP A07 demo
│   ├── idor_test.py     # OWASP A01 demo
│   ├── tamper_jwt.py    # OWASP A02 demo
│   ├── run_all_attacks.py
│   └── CyberShield_Postman_Collection.json
└── PROJECT_REPORT.html  # Full project report
```

---

## ⚡ Tech Stack

- **Java 21** + **Spring Boot 3.2.5**
- **Spring Security** + **JWT (HMAC-SHA384)**
- **PostgreSQL 16** + **Hibernate 6.4**
- **BCrypt strength-12** password hashing
- **BFS algorithm** for attack path traversal
- **Vanilla HTML/CSS/JS** frontend (9 pages)

---

*AICTE PYHack02 | CyberShield Nexus | Security Intelligence Platform*
