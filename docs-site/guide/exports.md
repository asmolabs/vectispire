# Exports

What gets a finding out of the dashboard and in front of the person who can act on it.

## SARIF 2.1.0

For GitHub code scanning, GitLab and Azure DevOps.

This is the export that matters most in practice, because it puts the finding **on the pull
request that introduced it** rather than on a dashboard somebody visits on Thursdays. A
finding annotated on the diff gets fixed; the same finding in a list gets triaged.

## OpenVEX

A VEX document built from your triage decisions — what you assessed as not affected, and
why.

Hand it to whoever consumes your SBOM. Without it they re-derive your entire backlog from
your dependency list and arrive at conclusions you already investigated and dismissed.

## CSV

Issues as a flat file, for the analysis somebody wants to run in their own tool.

## SBOM

The SBOM exactly as the cataloguer produced it, unmodified.

Worth being clear about why it is not reshaped: an SBOM is evidence, and evidence that
passed through a transformation is evidence about the transformation too.

## Documents written for people

Two PDF reports, written to be read rather than parsed:

- a target's **posture** — where it stands now;
- its **detection and triage history** — what was found, and what was decided about it.

See [History and evidence](history.md).

## Compliance evidence bundle

A cryptographically signed ZIP, covered under [Compliance](compliance.md).

## Project export

A whole project as one signed JSON document — the input a [report plugin](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0035-report-plugins.md)
will receive, and what an organisation writes its own plugin against before Vectispire runs anything.
There is no button yet: ask the route, with your session or an integration key holding the `export`
scope.

```bash
curl -H "X-API-Key: $KEY" -o export.zip https://vectispire.example.org/api/v1/projects/42/export
unzip export.zip                       # export.json and export.json.sig
cosign verify-blob --key public-key.pub --signature export.json.sig export.json
```

`public-key.pub` is `/api/v1/crypto/public-key.pub`, the key every Vectispire document is signed with.

**What it holds**, every part present even when empty — an empty list means "nothing", `null` means
"not recorded", never zero: the project and the repositories and images filed in it; each target's
newest completed scan (what it examined, what failed, each plugin's state) and the gate's last verdict;
every issue that is not resolved, with its triage decision; counts per type, severity, state and triage
status, resolved issues included; the consolidated components; the project's compliance state; and the
checklist statements — each signed-off one with the digest of its signed package, and the open revision
marked `draft`.

**What it never holds**: source code or anything quoted from it — an issue's text travels only for
vulnerabilities, licences and end of life, never a secret's or a rule's message; a secret's value; a
credential (a token in a repository URL is masked); an evidence file's bytes (named by SHA-256); an
e-mail address — people appear by account id and display name, and a display name that is an address
is left out.

**Who may take one**: an account that may act (not the platform governor) or an auditor, who sees the
**whole** project, its images included. Anybody else is told the project does not exist (404), the same
words as for a project that does not. An integration key restricted to one repository never sees a whole
project. Each download is audited (`PROJECT_EXPORTED`) and sent to the SIEM as `VECTI-SEC-032`.

**Bounded, never cut short**: over 100,000 issues or components, or 64 MiB of JSON, the export is
refused (409 `project-export-too-large`, naming the part, the figure and the bound) rather than signed
incomplete.

**Its schema** is `vectispire-project-export`, versioned `MAJOR.MINOR` and stated in the export's first
two fields. The installation serves the one it produces at `/api/v1/schemas/project-export/1`; the file
is [`v1.schema.json`](https://github.com/asmolabs/vectispire/blob/main/vectispire-java/vectispire-common/src/main/resources/schemas/project-export/v1.schema.json)
in the source. A minor only adds optional fields: a plugin must ignore what it does not know. A major is
a new file, and the release notes say when one appears and when the previous one stops being produced.

## Branding

Exports and reports carry your instance name where `VECTISPIRE_BRAND_NAME` is set —
header, PDFs, SARIF, VEX and CSAF output. See
[Configuration](../reference/configuration.md).
