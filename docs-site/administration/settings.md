# Settings

Most runtime configuration lives **in the database** and is edited here once the
application runs — enrichment, end-of-life, retention, notifications, licenses, tracker,
model review.

A setting appears on this page only once a service actually reads it. That rule keeps the
screen from becoming a museum of options that do nothing.

Only what is needed to reach this screen at all is an environment variable. See
[Configuration](../reference/configuration.md).

## Enrichment

EPSS and CISA KEV lookups. These are the only outbound calls the pipeline makes besides
the end-of-life catalogue, and they carry CVE identifiers and nothing else.

Turning them off is an option for an air-gapped deployment. It costs you the ability to
rank by exploitability, which is the ranking that works — see
[Reading the results](../getting-started/reading-results.md).

## End of life

The endoflife.date catalogue, carrying product names and versions. Coverage is deliberately
scoped to products — languages, runtimes, frameworks, distributions — rather than every
library.

## Licenses

The blocklist evaluated against SBOM data. What belongs on it is your organisation's
decision: AGPL is fatal for a proprietary distributed product and irrelevant for an
internal service that is never shipped.

## Retention

How long scans and their raw artefacts are kept. See
[Rotation and purge](maintenance.md).

## Notifications

Webhook, Teams and e-mail destinations, their secrets, and the weekly posture report.
Covered under [Notifications](../integrations/notifications.md).

## Tracker

GitLab or Jira: URL, project, token. Covered under
[Tracker tickets](../integrations/ticketing.md).

## AI code review

Off by default. A local LLM run via [Ollama](https://ollama.com) reviews source code with a
"security architect" prompt, as a lightweight complement to Grype, gitleaks and checkov —
not a replacement for any of them. When enabled it runs on repository scans, and its
narrative result and normalised findings appear in the scan detail.

Set the Ollama URL (default `http://localhost:11434`) and pick a model. The list is read
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
