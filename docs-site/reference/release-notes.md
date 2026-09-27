# Release notes

## Next release (after 0.9.0)

Not tagged yet. Read **Before you upgrade** first: three of its points stop something working
until an operator acts, on purpose.

### Before you upgrade

**Delegated scans stop until each delegating agent is updated and has a pinned signing key.**
An agent in `delegated` credentials mode receives a repository's SSH key or HTTPS token sealed for
its sealing key. That key is now accepted only when the agent signs it with the Ed25519 key an
administrator pinned ([decision 0031](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0031-a-sealing-key-is-believed-only-on-the-pinned-key.md)),
and no credential is ever sent in the clear, over TLS or not. Until an agent is updated **and** its
signing key is pinned, it claims no scan that needs a credential — those scans wait, pending and
costing no attempt, for an executor that can take them. Agents in `local` mode, image scans and
repositories without a credential are not affected. Before upgrading: pin each delegating agent's
signing key on the **Agents** screen, then update the agents. See
[Agents](../administration/agents.md).

**Secrets reach the containers as files, not as environment variables.** The shipped
`docker-compose.yml` now hands `ENCRYPTION_KEY`, the database passwords, the bootstrap password,
`VECTISPIRE_SIGNING_KEY` and the OIDC client secret over as Compose secrets under `/run/secrets/`:
a container's environment is readable by anything that can inspect it through the Docker daemon.
If you run your own composition or manifests, move these to files the same way
(`ENCRYPTION_KEY_FILE`, `spring.config.import: optional:configtree:/run/secrets/`). Your `.env`
must declare `VECTISPIRE_SIGNING_KEY` and `VECTISPIRE_OIDC_CLIENT_SECRET`, empty if unused:
Compose stops with the variable's name rather than dropping a signing key an installation was
using, because a replaced key makes every document already signed unverifiable.

**The database is no longer published on the host.** The `127.0.0.1:3306` port mapping is gone
and the database sits on an internal network. A tool that connected to it from the host needs
`docker compose exec` or a network of its own.

**Every request body has a ceiling.** 1 MB by default (`VECTISPIRE_MAX_BODY_DEFAULT`); routes
with their own keep it: VEX 16 MB, SARIF imports 32 MB, rule-set uploads 64 MB, agent results
256 MB. A client sending a larger body to an ordinary route now gets a 413.

**The KEV feed is CISA's catalogue, read from the network.** It was a list of ten records typed
into the code; the control plane now reads `known_exploited_vulnerabilities.json` every six hours
and from the **Threat Intelligence** settings tab, and a scan asks the stored copy instead of
downloading it. The control plane needs to reach `www.cisa.gov` — or set `VECTISPIRE_KEV_URL` to a
mirror (and `VECTISPIRE_KEV_ALLOW_PRIVATE=true` if it is on a private network), see
[Configuration](configuration.md#threat-intelligence). The upgrade empties the old feed: until the
first synchronisation, the status says *never synchronized* and a scan marks nothing as actively
exploited. That first synchronisation also **un-flags** open issues whose CVE the catalogue does not
list, including those the typed-in list had flagged.

**Schema migrations V32 to V43 run at start**, on MySQL and PostgreSQL. Back up the database
first, as for any upgrade — [backup and restore](https://github.com/asmolabs/vectispire/blob/main/docs/en/BACKUP_AND_RESTORE.md).

### Changes an integration can see

- A **413** is now always an RFC 9457 problem (`application/problem+json` with `detail`), also
  when refused on the declared length before reading.
- Granting a repository or an image that does not exist, or that the granting administrator
  cannot see, is refused with a **404**; a grant naming a missing project was a 400 and is a 404.
- An **API key restricted to a target** acts on that target only; a restriction no route would
  enforce is refused when the key is issued. A key restricted to a deleted target is revoked with
  it, and each revocation is audited under the key's id.
- Integration keys act for the account they belong to; an agent's key is confined to the agent
  routes (403 elsewhere).
- The threat-intelligence sync is audited as `THREAT_INTEL_SYNCED`, no longer `SETTING_UPDATED`;
  a change of certified scope is audited as `CERTIFIED_SCOPE_CHANGED`. A filter on the old
  operation stops finding syncs.
- Recording a gate verdict is a write: the auditor and the platform governor are refused.
- `GET /api/v1/threat-intel/status` and both sync routes answer the catalogue's version, its
  release date, the last attempt and its error; `status` is `NEVER_SYNCED`, `SYNCED` or `FAILED`.
  A sync that cannot read the catalogue answers **200** with `FAILED` and the reason, keeps the
  catalogue in use, and is audited as a failed `THREAT_INTEL_SYNCED`. `GET /api/v1/epss/cve/{id}`
  answers from the stored catalogue only — a **404** for a CVE it does not hold.
- An OWASP review is recorded before the model is asked: `GET …/owasp-review` may answer
  `status: running` while another request waits, and reads `failed` once the model's timeout has
  passed with nobody left to settle it.
- New finding types `plugin` and `imported`, and new fields on issues and scans (`tool`,
  `toolName`, `toolVersion`, `importSource`, a scan's `plugins[]`). The OpenAPI document in the
  repository is the contract.

### New

- **Solutions and projects**: a solution holds projects, a project references repositories, and a
  grant may name a whole project — [Solutions and projects](../administration/solutions-and-projects.md).
- **Analysis plugins**: third-party analysers packaged as container images, registered by the
  platform governor, switched on per project, run confined like the built-in scanners, only when
  a language they declare is present. An image may declare its signer; the signature is verified
  before the pull, and `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED` requires one for every plugin.
- **SARIF imports** from declared internal sources (a CI job, an on-premise SonarQube), each bound
  to one restricted key and one scope, with the provenance kept on every issue —
  [Plugins and SARIF imports](../administration/plugins.md). Gate policies count plugin and
  imported findings only when they say so (`include_plugins`).
- **Git over HTTPS** with a managed token bound to one host, beside SSH keys;
  `VECTISPIRE_GIT_ALLOWED_HOSTS` restricts where anything is cloned from.
- **SIEM export** over syslog UDP, TCP or TLS (RFC 5424, CEF), sent after commit —
  [SIEM export](../integrations/siem.md).
- **Parallel scans on an agent**, 1 to 16 at once (`max_concurrent`), counted by the database.
- **Resetting an agent's sealing key** from the Agents screen, for a host whose clock was put back
  or a key suspected of having leaked.
- Single sign-on records the provider's second factor and may require it
  (`VECTISPIRE_OIDC_REQUIRE_MFA`); Vault Transit may hold the encryption key.

### Security

This release closes the findings of the security review of 2026-09-26 and its follow-ups —
authentication limits under concurrent attempts, single sign-on linking, SSRF and parser
differentials on clone URLs, bounded outbound reads, audit and SIEM completeness, and the
agent's sealing key. Build dependencies and plugins are now verified against signatures and
checksums. The detail is in the commit history and in the
[decision register](https://github.com/asmolabs/vectispire/tree/main/docs/architecture/en/decisions).
