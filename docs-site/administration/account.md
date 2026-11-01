# Your account and the second factor

Every account can add a time-based second factor (TOTP) to its own sign-in, from **Account** in
the top bar.

This is distinct from the MFA your identity provider enforces. If you sign in through
[single sign-on](sso.md), the second factor is the realm's business and this page is not where it
is configured; the factor here protects accounts that sign in with a password.

## Enrolment happens in two steps, because that is what makes it safe

The server offers a secret, and **nothing is switched on until a first code has been verified**.

Without that confirmation a clock that is out of sync, or a secret copied wrong, would only show
at the next sign-out — that is, at the worst possible moment, to somebody who can no longer get
in to fix it.

A refused code keeps the enrolment open. Six digits with thirty seconds of life: getting one wrong
is ordinary, and reissuing a fresh secret over a typo would mean copying everything again.

**The confirmation asks for your current password too.** With a session alone, whoever held one —
stolen, or left open on a desk — could put your second factor on their own phone, and you would have
no code to remove it with. A wrong password counts against the account as a wrong sign-in does, and
past the same ceiling the confirmation answers `429`. An account that signs in only through the
provider has no password it knows, and no use for this factor.

## Locked out of your own factor

If the phone is gone and the recovery codes with it, or a factor you did not enrol is on the account,
an administrator resets it from the users screen: the factor is removed and your sessions close, and
you sign in with your password alone until you enrol again. If somebody else may have used the
account, ask for a password reset as well — that is what revokes the API keys.

## The recovery codes are shown once

The server stores them encrypted and will not return them again. The screen says so **before** showing them,
because the alternative is somebody closing the tab expecting to find them later.

Store them the way you store any other break-glass credential. They are the only way back in when
the phone is gone.

## There is no QR image, and that is said rather than hidden

Drawing one takes another dependency, which is not a decision to make in passing for a product
that pins every image by digest. The secret is shown in groups of four — the manual entry every
authenticator application accepts — and the `otpauth://` URI stays copyable.

## Removing the factor needs a code

Current or recovery, and it is the server that requires it. Without that, a workstation left
unlocked for a minute would be enough to disarm the factor protecting the account, which would
empty the protection of its meaning.

## Changing phones goes through removing the factor

Enrolling again while a factor is active is refused. Replacing it with no proof of the old one
would let anybody at an unlocked workstation move the account's second factor onto their own
phone; removing it asks for a code, so replacing it does too.

## A code opens once

A code accepted at sign-in, or to confirm the enrolment, is refused if presented again, even
inside its thirty seconds. A recovery code is spent the moment it is accepted, including by two
sign-ins presenting it at the same instant: only one of them gets in. If a code you have just
typed is refused, wait for the next one.

## Wrong codes count against the account

A sign-in challenge dies after three wrong codes, and the account absorbs **five wrong codes per
fifteen minutes across challenges**. Past that, sign-in answers `429` with `Retry-After` even
with the right password, and the right code clears the count. Only somebody who knows the
password can spend it — so if this happens to you and it was not you, change your password.

Password failures are counted per account, whatever spelling of the username opened it, and per
caller address as the server resolves it through the trusted proxies (`VECTISPIRE_TRUSTED_PROXIES`, see [installation](../getting-started/installation.md));
a `client_id` sent by the client is no longer read. An IPv6 caller counts as its /64: a host picks its
addresses within it at will. The name is folded as the database compares it — case, accents, and the
letters MySQL equates with others (`ß` and `ss`, `æ` and `ae`…) — so no spelling of an account gets a
counter of its own. A name no account can hold — anything but letters, digits, `.`, `_` and `-` — opens
no account at all, even where the database would have read past a soft hyphen or an invisible character:
it is refused like an unknown name, so sign in with the account's name as it was created. A successful sign-in clears the account's count
and the name's, not the address's: signing in to one's own account does not erase the failures the
same address made against others.

## Failures from many places

Three budgets count password failures over a sliding quarter of an hour: **five** per account (and per
name typed) from one address, **twenty** per address across every account, and **fifty** per account
from every address together. Each is a [setting](../reference/configuration.md#authentication).

The first two refuse with `429` and the code `rate-limited`. The third is the one a guess spread over
many addresses meets, and it **does not lock you out**: anyone who knows your username could otherwise
keep you out by failing fifty times from ten machines. Past it, a sign-in is refused with `429`, the
code `account-throttled` and `Retry-After` only when it comes from an address that has not signed in to
the account in the last thirty days (`VECTISPIRE_SIGN_IN_KNOWN_CLIENT_RETENTION`). From your usual
place you sign in as usual, held to that address's own five. From a new place:

- **with a second factor**, type your code under the password — the sign-in screen shows the field
  once it has been refused this way. The password and the code are checked together, and the answer is
  a session or the same refusal, whichever of the two was wrong;
- **without one**, wait for the time shown, or sign in from a device you have used before.

The refusal comes before the password is checked, and says nothing about whether the account exists:
an unknown name past its budget is refused the same way. Each refusal is in the
[audit log](audit-log.md) as `LOGIN_BLOCKED` (signalled `VECTI-SEC-007`), and the server logs one
warning per account and quarter of an hour while its budget is spent. If you see it on your account,
somebody is guessing your password: make it a long one, and enrol a second factor.

"Address" is the address the server resolves through the trusted proxies, its /64 in IPv6 — so somebody
behind the same office egress as you shares your exemption, and meets that address's own ceilings
instead.

## Related

- [Single sign-on](sso.md) — delegating authentication, and the second factor, to a provider.
- [Users and teams](users-and-teams.md) — roles, and what each one may do.
