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
   * When an engineering lead or developer closes the ticket in Jira, GitLab, GitHub, or ServiceNow with a disposition Vectispire can read, Vectispire receives the inbound webhook event and reads it as one of two different claims:
     * **A refusal** — *Won't Fix*, *Declined*, *Rejected*, *Risk Accepted*, *Withdrawn*, or GitHub's `not_planned` — says the team will not fix it. It is proposed as **`will_not_fix`** (*Will not fix — risk accepted*), with **no** VEX justification and a proposed review date ninety days out; whoever grants it sets their own. A refusal says nothing about whether the product is exposed, so it is never turned into `not_affected`: until 0.11.0 it was, with the justification `inline_mitigations_already_exist` — a mitigation nobody had built, which the signed documents would have carried once approved ([decision 0041](../architecture/en/decisions/0041-will-not-fix-is-not-not-affected.md)).
     * **An explicit false positive** — *False Positive*, *Cannot Reproduce*, *Not an Issue*, or the words "false positive" in a GitHub or GitLab issue — is a claim about exposure, and only it is proposed as **`not_affected`**, with the justification `vulnerable_code_not_in_execute_path`.
   * Either way the decision is **queued for approval by a second person**, not applied: the issue moves to `pending_approval`, and the exported documents show it as under investigation until someone approves it. A tracker is neither a person nor authenticated as one, and what is granted travels as it stands into the signed CycloneDX, OpenVEX and CSAF documents. The event is recorded in the hash-chained audit log under `TICKET_SYNCED`.
   * **A decision a person settled is not moved by a ticket.** On an issue already `not_affected`, `will_not_fix` or `fixed`, the tracker's word is recorded in the audit log and nothing changes. When it disagrees with the settled status — *Won't Fix* on an issue cleared as not affected, say — the entry is `TRIAGE_CONTRADICTED_BY_TRACKER`, sent to the SIEM as `VECTI-SEC-037`: one of the two is wrong, and only a person can say which.

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
* **Behavior**: A resolution of *"Won't Fix"*, *"Declined"* or *"Rejected"* queues a `will_not_fix` request for approval; *"False Positive"* or *"Cannot Reproduce"* queues a `not_affected` one.

### 2. 🦊 GitLab Issues
* **Webhook URL**: `https://<VECTISPIRE_HOST>/api/v1/tickets/webhook/gitlab`
* **Events**: `Issues Events`
* **Behavior**: An issue whose title or description says *"false positive"* queues a `not_affected` request for approval; an issue closed with *"wontfix"* or *"won't fix"* in its title queues a `will_not_fix` one.

### 3. 🐙 GitHub Issues
* **Webhook URL**: `https://<VECTISPIRE_HOST>/api/v1/tickets/webhook/github`
* **Events**: `Issues` (action `closed` / `labeled`)
* **Behavior**: An issue closed as *not planned* (`state_reason: not_planned`) queues a `will_not_fix` request for approval — it is GitHub's only way to close without completing, and says nothing about reachability. Only the words *"false positive"* in the issue's body queue a `not_affected` one.

### 4. 🏢 ServiceNow (Incident Table API)
* **Webhook URL**: `https://<VECTISPIRE_HOST>/api/v1/tickets/webhook/servicenow`
* **Events**: Incident State Change (Close Code: *"Won't Fix"*, *"Solved"*, *"False Positive"*)
* **Behavior**: A close code of *"Won't Fix"*, *"Risk Accepted"* or *"Withdrawn"* queues a `will_not_fix` request for approval; *"False Positive"* or *"Not an Issue"* queues a `not_affected` one.

---

## 🔒 Security & Token Encryption

* Tracker credentials (`TICKET_TOKEN`) are encrypted at rest with AES-GCM-256 bound to key context `setting:ticket_token`.
* A delivery is acted on once: its body is remembered for thirty days, so a captured signed request sent again later is answered *"Delivery already processed"* and changes nothing. The tracker's own redelivery of the same event lands there too.
* Every synchronization update is recorded in the cryptographically chained audit log.
