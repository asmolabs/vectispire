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

## Branding

Exports and reports carry your instance name where `VECTISPIRE_BRAND_NAME` is set —
header, PDFs, SARIF, VEX and CSAF output. See
[Configuration](../reference/configuration.md).
