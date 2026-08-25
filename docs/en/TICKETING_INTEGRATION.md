# Bidirectional Ticketing Integration Guide (Jira, GitLab, GitHub, ServiceNow)

Vectispire provides an automated bidirectional synchronization engine between its ASPM vulnerability backlog and development issue tracking systems (Jira, GitLab Issues, GitHub Issues, ServiceNow).

---

## 🎯 Key Features

1. **Automatic Ticket Creation**:
   * When a critical or blocking vulnerability is discovered (per active Quality Gate policy), Vectispire automatically opens a ticket with full remediation context, CVSS/EPSS scores, evidence links, and file locations.
   * The ticket reference and URL are permanently linked to the Vectispire issue (`ticketRef`, `ticketUrl`).

2. **Automatic Ticket Closure on Resolution**:
   * As soon as a subsequent security scan verifies that the vulnerability has been fixed (issue state transitions to `RESOLVED`), Vectispire calls the tracker API to automatically close the ticket with a resolution note: *"✅ Issue resolved by Vectispire security scan"*.

3. **Status Sync & Triage Decisions (Inbound Webhooks)**:
   * When an engineering lead or developer updates the ticket in Jira, GitLab, GitHub, or ServiceNow with a disposition such as *False Positive*, *Won't Fix*, *Declined*, or *Risk Accepted*, Vectispire receives the inbound webhook event.
   * The issue in Vectispire is immediately triaged to **`not_affected`** with the appropriate OpenVEX / CSAF justification, and an immutable log entry is added to the cryptographic audit trail under `TICKET_SYNCED`.

---

## 🛠️ Inbound Webhook Configuration

Add the following webhook endpoints in your external issue tracker:

### 1. 🏷️ Jira Software (Atlassian)
* **Webhook URL**: `https://<VECTISPIRE_HOST>/api/v1/tickets/webhook/jira`
* **Events**: `Issue -> updated`
* **Behavior**: If the resolution is marked as *"Won't Fix"*, *"False Positive"*, or *"Declined"*, Vectispire updates the issue triage status automatically.

### 2. 🦊 GitLab Issues
* **Webhook URL**: `https://<VECTISPIRE_HOST>/api/v1/tickets/webhook/gitlab`
* **Events**: `Issues Events`
* **Behavior**: When an issue is closed or commented with *"false positive"* or *"wontfix"*, status is automatically mirrored in Vectispire.

### 3. 🐙 GitHub Issues
* **Webhook URL**: `https://<VECTISPIRE_HOST>/api/v1/tickets/webhook/github`
* **Events**: `Issues` (action `closed` / `labeled`)

### 4. 🏢 ServiceNow (Incident Table API)
* **Webhook URL**: `https://<VECTISPIRE_HOST>/api/v1/tickets/webhook/servicenow`
* **Events**: Incident State Change (Close Code: *"Won't Fix"*, *"Solved"*, *"False Positive"*)

---

## 🔒 Security & Token Encryption

* Tracker credentials (`TICKET_TOKEN`) are encrypted at rest with AES-GCM-256 bound to key context `setting:ticket_token`.
* Webhook ingestion is stateless and idempotent.
* Every synchronization update is recorded in the cryptographically chained audit log.
