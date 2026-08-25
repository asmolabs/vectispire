# Architecture Document — 02. Security View

* **Project:** Vectispire — ASPM & Security Control Plane
* **Template:** `bflorat/modele-da` — Architecture Document Template (Bertrand Florat)
* **Status:** Approved · **Version:** 1.0

---

## 1. Non-Functional Security Requirements (NFR)

1. **Data Confidentiality at Rest**: Systematic encryption of integration secrets and private SSH deployment keys.
2. **Watertight Source Code Isolation**: Zero risk of source code exfiltration by scanner containers.
3. **Audit Log Tamper-Proofing**: Inability to modify administrative action traces or VEX triage decisions.
4. **Least Privilege for Remote Agents**: Remote agents cannot reach the SQL database — enforced by the module graph, so the violation fails to compile — and never hold `ENCRYPTION_KEY`. They *do* receive repository deployment keys in `DELEGATED` mode, sealed to the public key the agent announced at enrolment (X25519 → HKDF → AES-256-GCM) and audited on every send; `LOCAL`, the default, sends nothing. Stated in full rather than as "agents hold no credentials", which is the shorter claim and the false one — see [decision 0003](../../en/decisions/0003-long-polling-for-agents.md).

---

## 2. Authentication, Session Security & RBAC

### 2.1 Password Hashing & Anti-Brute-Force Protection
- **User Passwords**: Hashed using **Argon2id** algorithm (high memory cost, resistant to GPU cracking).
- **In-Memory Dynamic Token-Bucket Rate-Limiting (`Bucket4j`)**: `LoginRateLimitFilter` HTTP filter intercepting `POST /api/v1/auth/login` (Bucket4j: 10 tokens per minute per IP). Blocks burst attacks instantly with HTTP `429 Too Many Requests` and `Retry-After` headers **without performing any database query or Argon2id key derivation**.
- **Persistent Brute-Force Protection (`t_login_attempt`)**: Tracks failed login attempts per username and client ID in database via `LoginThrottle`.
- **CI/CD Integration API Keys**: Stored strictly as Argon2id hashes (`vectispire_` prefix) with configurable permission scopes and expiration dates.

### 2.2 Role-Based Access Control (RBAC) & Double Validation
Strict endpoint authorization via Spring Security:
- `ROLE_ADMIN` / `ROLE_SUPERUSER` / `ROLE_CISO`: System configuration, user management, SSH keys, and toggling **Double Validation (Four-Eyes Approval)** (`triage_four_eyes_required`).
- **Optional Double Validation**: Dynamically configurable via UI by Admins or CISOs (`PUT /api/v1/settings`). When enabled, any VEX triage decision (`NOT_AFFECTED` or `FIXED`) submitted by a non-CISO/Admin user enters `PENDING_APPROVAL` status. When disabled, authorized users can directly triage issues.
- **Distinct Identities Enforced**: The approver is checked against the requester recorded on the `PENDING_APPROVAL` event, not merely against the approver role. An account that requests an exemption cannot approve it, even after being granted the role — four eyes means two people, and a role gate alone lets one person hold both halves.
- **Audit Logging**: Any toggle change to double validation is immediately recorded in the SHA-256 sealed audit log (`t_audit_log`) with operator identity (`SETTING_UPDATED`).
- `ROLE_USER` / `ROLE_SECURITY_CHAMPION`: Posture dashboard inspection and vulnerability triage.
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
