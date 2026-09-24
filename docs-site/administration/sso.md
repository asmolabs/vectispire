# Single sign-on

Optional **OpenID Connect**, tested against Keycloak.

## What the provider decides, and what it does not

The provider answers exactly one question: *who is this?*

Vectispire still issues its own session. The visibility rules, the audit trail, the session
lifetimes and the API keys all keep working unchanged, because none of them were delegated.

## No account is created on sign-on

This is the part worth reading twice.

An administrator creates the account first, and the **role stays Vectispire's to decide**.
Whoever can obtain a token from a shared realm must not thereby obtain a reader's view of
every target — and in a shared realm, that is a much larger set of people than the ones you
meant to let in.

## Binding an identity

The **first** sign-on binds the account whose username matches the claim.

Every later one matches on the provider's **subject**, not the username. A username is not
stable for the life of a person: people marry, change teams, get renamed by an HR import.
The subject is.

## Groups become teams, and leaving one takes it away

When the token carries a `groups` claim, each value is matched against a **team name** and the
account joins the teams that match.

It also **leaves** the ones no longer claimed — but only the ones the provider granted. A team an
administrator assigned by hand, or SCIM provisioned, is never removed by a sign-on: each channel
reconciles its own memberships, so two directories cannot undo each other's work and a login cannot
silently erase somebody's deliberate decision.

An **empty or absent claim removes nothing**. A forgotten mapper is a configuration fault, not a
statement that this person belongs to no team, and revoking on that basis would cut everybody off
the first time a mapper was misconfigured.

## Provisioning from the directory (SCIM)

An identity provider can create, update, deactivate and delete accounts through SCIM 2.0
(`/scim/v2/Users`, `/scim/v2/Groups`), authenticated by the SCIM bearer token. That token lives in
the provider's configuration, so what it may do is deliberately bounded:

- **Administrative accounts are not the directory's to change.** Replacing, patching or deleting an
  administrator or a superuser answers `403`; they are administered in Vectispire.
- **The directory grants non-administrative roles only.** A `roles` value of `ADMIN` or `SUPERUSER`
  answers `400`.
- **A replacement without `roles` leaves the role as it is** — it no longer demotes to User.
- **`externalId` is bound once.** Changing it on an account that already has one answers `400`: a
  new subject means a new account.
- **A role change closes the account's sessions**, as a deactivation does.

## Configuration

```bash
VECTISPIRE_OIDC_ISSUER=https://keycloak.internal/realms/company
```

Plus the client credentials your provider issues.

### What the compliance report says about it

The audit log's controls are **capped while authentication is weaker than the report claims**. No
provider at all caps them at 65 %: the hash chain proves an entry was not altered, it cannot prove
the name on it belongs to whoever acted. A provider *beside* an open password caps them at 85 % —
the realm's second factor can be walked around through the other door.

This is deliberately a number rather than a refusal. PCI DSS and SOC 2 both require a second
factor, and a report that scored them compliant while Vectispire accepted a password alone was
handing an assessor their own diligence back as a conclusion.

### Turning off password login

```bash
VECTISPIRE_PASSWORD_LOGIN=false
```

Authentication is then delegated entirely, and the second factor is the realm's.

This is **ignored, loudly**, when no `VECTISPIRE_OIDC_ISSUER` is set. Honouring it would
leave no way in at all, and a security tool that locks its administrators out has not
become more secure.

## Related

[Users and teams](users-and-teams.md) · [Configuration](../reference/configuration.md)
