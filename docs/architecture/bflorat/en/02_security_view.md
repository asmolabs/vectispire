# Architecture Document — 02. Security View

* **Project:** Vectispire — ASPM & Security Control Plane
* **Template:** `bflorat/modele-da` — Architecture Document Template (Bertrand Florat)
* **Status:** Approved · **Version:** 1.0

---

## 1. Non-Functional Security Requirements (NFR)

1. **Data Confidentiality at Rest**: Systematic encryption of integration secrets and private SSH deployment keys.
2. **Watertight Source Code Isolation**: Zero risk of source code exfiltration by scanner containers.
3. **Audit Log Tamper-Proofing**: Inability to modify administrative action traces or VEX triage decisions.
4. **Least Privilege for Remote Agents**: Absolute restriction prohibiting remote agents from connecting directly to the SQL database.

---

## 2. Authentication, Session Security & RBAC

### 2.1 Password Hashing & API Keys
- **User Passwords**: Hashed using **Argon2id** algorithm (high memory cost, resistant to GPU cracking).
- **Brute-Force Protection**: Tracking failed login attempts in `t_login_attempt` with automatic lockout.
- **CI/CD Integration API Keys**: Stored strictly as Argon2id hashes (`vectispire_` prefix) with configurable permission scopes and expiration dates.

### 2.2 Role-Based Access Control (RBAC)
Strict endpoint authorization via Spring Security `@PreAuthorize`:
- `ROLE_ADMIN`: User management, SSH key administration, Quality Gate policies, system configuration.
- `ROLE_USER` / `ROLE_ANALYST`: Posture dashboard inspection, vulnerability VEX qualification.
- `ROLE_CI`: Dedicated Gate evaluation execution (`POST /api/v1/gate`).

---

## 3. Data Protection at Rest & Encryption

### 3.1 AES-256-GCM Encryption (`EncryptionService`)
All private SSH deployment keys (`t_ssh_key`) and integration tokens are encrypted using **AES-256-GCM** authenticated encryption (AEAD). Master encryption key is loaded from `ENCRYPTION_KEY` environment variable.

### 3.2 Secret Retention & Purge
1. **Raw Scanner Outputs**: JSON payloads temporarily held in `scan.cves` are purged automatically by `RetentionService`.
2. **Minimal Finding Storage**: `Finding` and `Issue` entities store **only file path and line number**, never cleartext secret values.

---

## 4. Analysis Container Confinement

All analyzer containers executed by `ContainerRunner` are hardened to prevent escape or exfiltration:

| Security Measure | Implementation | Confinement Objective |
|---|---|---|
| **Privilege Dropping** | `cap_drop: ALL`, `no-new-privileges` | Prevent root privilege escalation inside container. |
| **Read-Only Volume Mount** | Source mounted as `read-only` | Guarantee analyzer never modifies scanned code. |
| **Network Isolation** | **`network: none`** (Secrets, SAST, IaC) | Prevent code or secret exfiltration. |
| **Docker Socket Access** | **No Docker socket access** | Prohibit takeover of host Docker daemon. |

---

## 5. Audit Log Tamper-Proofing (Cryptographic Sealing)

The `t_audit_log` table stores historical administrative and VEX triage records. Each row incorporates a SHA-256 hash calculated from the current entry and the preceding row's hash:

```
Hash_N = SHA256( Id_N + Action_N + User_N + Timestamp_N + Hash_N-1 )
```

`AuditLogService.verifyIntegrity()` verifies chain integrity automatically and flags any SQL modification or deletion.

---

## 6. STRIDE Threat Model

Full threat modeling based on **DFD STRIDE per System Entity** is documented separately in [`STRIDE_THREAT_MODEL.en.md`](../../security/en/STRIDE_THREAT_MODEL.en.md).
