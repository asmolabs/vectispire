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
