# Bidirectional Ticketing Integration Guide (Jira, GitLab, GitHub, ServiceNow)

Vectispire provides an automated bidirectional synchronization engine between its ASPM vulnerability backlog and development issue tracking systems (Jira, GitLab Issues, GitHub Issues, ServiceNow).

---

## 🎯 Key Features

1. **Automatic Ticket Creation**:
   * When a critical or blocking vulnerability is discovered (per active Quality Gate policy), Vectispire automatically opens a ticket with full remediation context, CVSS/EPSS scores, evidence links, and file locations.
   * The ticket reference and URL are permanently linked to the Vectispire issue (`ticketRef`, `ticketUrl`).

2. **Automatic Ticket Closure on Resolution**:
   * As soon as a subsequent security scan verifies that the vulnerability has been fixed (issue state transitions to `RESOLVED`), Vectispire calls the tracker API to automatically close the ticket with a resolution note: *"✅ Issue resolved by Vectispire security scan"*.
   * **Only a ticket Vectispire opened is closed this way.** A reference a person attached by hand names a ticket somebody else may own, so it is theirs to close. And a reference is accepted only in the configured tracker's own shape — `#123` for GitLab and GitHub, `KEY-123` in the configured project for Jira, a sys_id or an incident number for ServiceNow — because it becomes part of a URL sent with the integration's token.
   * **ServiceNow is closed by `sys_id`.** The reference kept is the incident number people read (`INC0012345`), but the Table API addresses a record by `sys_id` only, so Vectispire first queries `/api/now/table/incident?sysparm_query=number=…&sysparm_fields=sys_id` and then `PATCH`es that record — the account needs read access on `incident` as well as write. A reference that is already a `sys_id` is used as it is. GitLab issues are closed with `PUT`, GitHub issues with `PATCH`; until this was fixed every close went out as a `POST`, which neither GitLab nor ServiceNow routes, and failed.

3. **Status Sync & Triage Decisions (Inbound Webhooks)**:
   * When an engineering lead or developer updates the ticket in Jira, GitLab, GitHub, or ServiceNow with a disposition such as *False Positive*, *Won't Fix*, *Declined*, or *Risk Accepted*, Vectispire receives the inbound webhook event.
   * The issue in Vectispire is immediately triaged to **`not_affected`** with the appropriate OpenVEX / CSAF justification, and an immutable log entry is added to the cryptographic audit trail under `TICKET_SYNCED`.

---

## 🛠️ Inbound Webhook Configuration

Add the following webhook endpoints in your external issue tracker:

> **Set the webhook secret first** (**Settings → Tickets → Inbound webhook secret**), and the same
> value in the tracker. The route cannot hold a session, so the secret is its whole authentication:
> **without one it refuses every call** with `403` and *"The ticket webhook is not configured on
> this instance"*, which is what the tracker's delivery log shows. A stored secret that no
> configured key can decrypt — `ENCRYPTION_KEY` lost, or an old key dropped from
> `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS` — refuses with `401`, and the settings screen shows it as not
> configured: set it again. How each tracker presents it: GitLab in `X-Gitlab-Token`, GitHub as the
> `X-Hub-Signature-256` HMAC of the body, Jira and ServiceNow in `X-Vectispire-Token`.

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
* A delivery is acted on once: its body is remembered for thirty days, so a captured signed request sent again later is answered *"Delivery already processed"* and changes nothing. The tracker's own redelivery of the same event lands there too.
* Every synchronization update is recorded in the cryptographically chained audit log.
