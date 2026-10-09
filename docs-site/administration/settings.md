# Settings

Most runtime configuration lives **in the database** and is edited here once the
application runs — enrichment, end-of-life, retention, notifications, licenses, tracker,
model review.

A setting appears on this page only once a service actually reads it. That rule keeps the
screen from becoming a museum of options that do nothing.

Only what is needed to reach this screen at all is an environment variable. See
[Configuration](../reference/configuration.md).

## Who may change what

A CISO writes most of this page, but **not where a credential is sent**. The tracker token and
the OpenAI key are set by an administrator only, so the settings that decide their destination —
the tracker base URL, *Allow a private tracker URL*, the OpenAI URL and the acknowledgement that
lets code go to a remote endpoint — are an administrator's too, and show read-only to anyone else.
Otherwise a role that cannot read a credential could collect it by pointing it at its own host.
*Allow a private SIEM destination* is an administrator's for a neighbouring reason: the SIEM export is
configured and tested by a CISO, and the switch deciding whether it may reach the internal network
is not left to the same role.

Three settings decide rules rather than parameters and are a **platform governor's** only — who
sees which targets, whether a triage takes [two people](four-eyes.md), and whether Vectispire answers
the measured lines of a checklist (below): whoever acts under a rule does not lift it.

The SIEM form works the other way round, because the same role sets its endpoint and its header:
changing the endpoint **drops the stored header** unless a new one is typed with it. A header is
issued for one collector. It is sent with the webhook only, and refused with a syslog protocol — see
[SIEM export](../integrations/siem.md) for the protocols, the endpoint each reads and the events sent.

## How long a value may be

A text setting holds up to 16,000 characters, and a credential — the tracker token, the webhook
secrets, the OpenAI key — up to 8,192. Longer is refused with a message at the form. Real tokens
are far shorter: before this limit, any credential over about 160 characters could not be saved at
all.

## Default rescan interval

On the **Scanners** tab, under *Scheduling*: how often a repository or an image is rescanned when it
has neither an interval nor a cron expression of its own — which is every target added without
touching its schedule. **Seven days** unless changed (0.11.0). A target's own interval or expression
always wins, and a target set to *manual only* is never rescanned.

Each target has its own moment in the interval, derived from its identifier, so an estate of a
thousand targets is spread over the week — a handful an hour — rather than queued in one minute, and
each keeps its moment from one round to the next. A round is skipped when a scan of the target is
already waiting or running.

**Zero means no default**: a target without a schedule of its own is then not rescanned, which is
how every version before 0.11.0 behaved. Changing the value moves the moments; switching it on after
a period at zero makes every target that was never scheduled due at once, so expect one busy hour.

## Enrichment

EPSS scores and CISA KEV status, both read from copies the control plane synchronises — CISA's
catalogue every six hours, FIRST's daily EPSS file once a day, or the mirrors `VECTISPIRE_KEV_URL`
and `VECTISPIRE_EPSS_URL` name ([Configuration](../reference/configuration.md#threat-intelligence)) —
each shown with its date on the **Threat Intelligence** tab. A scan asks neither: the list of CVE a
repository carries never leaves the control plane.

An air-gapped deployment keeps enrichment on and points both variables at mirrors inside the
estate. Turning it off costs you the ability to rank by exploitability, which is the ranking that
works — see [Reading the results](../getting-started/reading-results.md).

## End of life

The endoflife.date catalogue, carrying product names and versions. Coverage is deliberately
scoped to products — languages, runtimes, frameworks, distributions — rather than every
library.

## Licenses

The blocklist evaluated against SBOM data. What belongs on it is your organisation's
decision: AGPL is fatal for a proprietary distributed product and irrelevant for an
internal service that is never shipped.

## Security checklists

**Answer measured checklist lines automatically** (`checklist_auto_answer`, **on by default**) decides
whether Vectispire answers the lines of a draft [security checklist](../guide/security-checklists.md#automatic-answers)
that a rule measures — *yes* when the measurement is met, *no* with the measurement as its comment when
it is not, nothing without data — when a scan or an import completes on one of the project's
repositories, and when a checklist is opened or moved to another version. Its answers are marked as
Vectispire's, never replace a person's, and submitting and signing off stay acts of people.

It decides who may write an answer in a document people sign, so it is a rule rather than a
parameter: **only a platform governor changes it**, and a change is audited and signalled to the SIEM
as a security setting. Switched off, nothing new is answered automatically; the answers already
written stay until somebody answers over them, and answering as measured in one click remains.

## Retention

How long scans and their raw artefacts are kept, and — apart from them — how long the evidence
is: *Evidence kept for (days)* (`evidence_retention_days`). See
[Rotation and purge](maintenance.md).

## Notifications

Webhook, Teams and e-mail destinations, their secrets, and the weekly posture report.
Covered under [Notifications](../integrations/notifications.md).

## Tracker

GitLab, GitHub, Jira or ServiceNow: URL, project, token. Covered under
[Tracker tickets](../integrations/ticketing.md).

## AI review

Off by default. **Today the switch turns on one thing: the [OWASP report written by a
model](../guide/risk-analysis.md#the-owasp-report-written-by-a-model)**, asked from the OWASP page or,
with `ai_review_owasp_after_scan`, after each repository scan. The model is sent the repository's open
findings — identifiers, components, paths, descriptions — not the repository's source, though a
description can quote a line of it.

**No scan reviews the code with a model.** The "security architect" prompt, the reading of its answer
into findings and the finding type that would carry them exist, but no scan step calls them: a scan
with this switch on examines exactly what it examines with it off, and no finding comes from a model.
This paragraph said otherwise until 0.11.0. When that review is wired, its findings will be tagged as
coming from a model and excluded from the gate by default — the code it reads is written by whoever is
being audited, and can try to steer it.

What the provider warnings below say about the code applies to what is sent today, the findings, and
to the source the day the code review exists.

**The provider decides where the code goes** (`ai_review_provider`):

- **`ollama`** (the default) — a model on a machine you run.
- **`openai`** — any endpoint speaking the OpenAI chat-completions protocol, at
  `ai_review_openai_url` (default `https://api.openai.com/v1`), with `ai_review_openai_key` (stored
  encrypted, never returned) and `ai_review_model`. Left at OpenAI's address, **the source of every
  scanned repository — private ones included, and any secret still committed in them — is sent to
  OpenAI**, a third party applying its own retention and jurisdiction. Check your contract with the
  provider on retention and training, and whether the code you scan is yours to send. Pointed at
  vLLM, LM Studio, llama.cpp or an internal gateway, the code stays on your network.

**A public endpoint is refused until it is acknowledged.** Both URLs go through the outbound guard;
a destination outside your network — OpenAI's API, or a public Ollama — needs **Allow a public model
endpoint** (`ai_review_allow_remote_url`, off by default). Turning it on records, server-side, the
account that accepted the risk and when (`ai_review_risk_acknowledged_by` / `_at`, and the audit
log); turning it off clears them. `ai_review_timeout_seconds` (default 300) bounds the wait.

**The OWASP report after each scan** (`ai_review_owasp_after_scan`, off by default, inert while model
review is off). On, a repository scan that completes asks the model for that repository's
[OWASP report](../guide/risk-analysis.md#the-owasp-report-written-by-a-model) — its open findings,
never its source — one report at a time, beside the scans and never holding one up. Expect a model
call of a few minutes per scanned repository, which is why it is off.

### With Ollama

Set the Ollama URL (`ai_review_ollama_url`, default `http://localhost:11434`) and pick a model. The list is read
live from Ollama's own `/api/tags`, so whatever you have actually pulled shows up. If
Ollama is unreachable the dropdown falls back to two suggestions rather than being empty —
which is also the symptom to recognise.

There is deliberately no setting for *where* Ollama runs. Native or containerised,
Vectispire talks to it over plain HTTP either way, and the choice is about GPU access on
your host rather than about anything Vectispire does.

```bash
ollama pull gemma4:12b-it-qat   # ~7.2 GB, ~9–10 GB RAM/VRAM — recommended
ollama pull gemma4:e4b-it-qat   # ~6.1 GB, lighter and faster, lower review quality
```

!!! note "Apple Silicon"
    Docker Desktop has no GPU or Metal passthrough on Apple Silicon, so a containerised
    Ollama runs CPU-only and inference is noticeably slower. Install natively there.

## Branding

`VECTISPIRE_BRAND_NAME` sets the instance name shown in the header, the PDF reports and
the SARIF, VEX and CSAF exports.
