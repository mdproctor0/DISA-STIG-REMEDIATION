# 🛡️ DISA STIG Remediation – Windows 10 (PowerShell)

> **Hands-on Windows 10 DISA STIG remediations with manual validation and automated PowerShell enforcement.**

This repository demonstrates **real-world vulnerability remediation workflows**, not just scripts.

✔ Manual fixes  
✔ Verified rescans  
✔ Rollback testing  
✔ Automated enforcement  
✔ Audit-ready documentation  

---

## 🚨 Why This Project Exists

DISA STIG findings aren’t fixed by clicking buttons — they’re fixed by:
- Understanding **why** a control exists
- Applying it **correctly**
- Verifying compliance
- Automating it **safely and repeatably**

This project simulates **enterprise and DoD-style security hardening** using the same workflows used in real environments.

---

## 🧭 Remediation Workflow (Real-World Methodology)

Each STIG follows this exact process:


### Step-by-step:
1. Run Windows 10 DISA STIG scan
2. Identify failed finding
3. Research and apply manual remediation
4. Rescan to confirm **PASS**
5. Revert change to validate **FAIL**
6. Implement fix using PowerShell
7. Rescan again to confirm **PASS**
8. Document and publish remediation

This mirrors how vulnerability management is done in production environments.

---

## 🧩 Implemented STIGs

### 🔐 Account & Password Security
| STIG ID | Description |
|------|------------|
| WN10-AC-000005 | Account lockout duration |
| WN10-AC-000010 | Account lockout threshold |
| WN10-AC-000015 | Reset lockout counter |
| WN10-AC-000020 | Password history |
| WN10-AC-000030 | Minimum password age |
| WN10-AC-000035 | Minimum password length |
| WN10-AC-000040 | Password complexity |

---

### ⚙️ System Hardening
| STIG ID | Description |
|------|------------|
| WN10-00-000155 | Disable PowerShell 2.0 |
| WN10-00-000175 | Disable Secondary Logon |

---

### 📊 Auditing & Logging
| STIG ID | Description |
|------|------------|
| WN10-AU-000500 | Application event log max size |

Each remediation is implemented as an **independent PowerShell script** named after the STIG ID for traceability.

