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

## The recovery codes are shown once

The server hashes them and will not return them again. The screen says so **before** showing them,
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

## Related

- [Single sign-on](sso.md) — delegating authentication, and the second factor, to a provider.
- [Users and teams](users-and-teams.md) — roles, and what each one may do.
