# The licences of what Vectispire distributes

*Version française : [`docs/fr/LICENSES.fr.md`](../fr/LICENSES.fr.md).*

Vectispire is distributed under Apache-2.0 as two jars, three container images and the interface
compiled into the control plane's jar. Each of those carries other people's code, and this page says
how it is checked that their licences permit it. [`NOTICE`](../../NOTICE) lists the components.

## What is checked, and where

| What ships | Read from | Checked by |
|---|---|---|
| The runtime jars inside `vectispire-core.jar` and `vectispire-agent.jar` | the SBOMs the `sbom` job builds with Syft | `licences` (ci.yml) |
| The npm packages the interface is built from | `package-lock.json`, development dependencies aside | `licences` |
| The operating-system packages of the three images | SBOMs of the images `images` has just built | `images` |
| `NOTICE` | every jar under another licence than Apache-2.0 must be named in it | `licences` |

All three run [`ci/licences/check.py`](../../ci/licences/check.py) against
[`ci/licences/allowed.txt`](../../ci/licences/allowed.txt), which holds two kinds of line:

- **licences** permitted, each with the reason it can ship inside an Apache-2.0 distribution, and a
  scope: GPL and LGPL are permitted for an image's packages — separate programs aggregated beside the
  jar — and for no jar and no npm package;
- **components** reviewed one by one: metadata missing (docker-java, JGit), ambiguous (dual licences
  such as Logback's EPL-2.0 or LGPL-2.1, recorded as the one taken) or naming a licence outside the
  list. Such a line vouches for the licence ids the metadata declared when it was read, and for
  nothing else: a new version declaring another licence fails until it is read again.

A component under a licence nobody reviewed fails, and so does one with no licence at all. The answer
is a decision recorded in that file with its reason, or another dependency; a licence that does not
permit distribution under Apache-2.0 — GPL or AGPL in a jar or the interface, SSPL, the Commons
Clause — is never added. A run that read no component fails too.

## The state at 1.0.0 (audit of 2026-10-30)

- **Jars**: 156 components in the control plane, 51 in the agent. Apache-2.0 for the large majority;
  MIT, BSD-2-Clause, BSD-3-Clause (EDL-1.0 included), CC0 and EPL-2.0 for the rest. EPL-2.0 is a
  file-level copyleft whose files ship unmodified, their source upstream.
- **The interface**: 74 packages in the dependency tree, MIT, ISC, Apache-2.0, BSD and 0BSD, and
  MPL-2.0 for `lightningcss`, a build tool of Tailwind's that does not reach the bundle. The bundle's
  own notices are `static/licenses/3rdpartylicenses.txt`, written by `ng build`.
- **Images**: 44 Alpine packages in the control plane's and the agent's images, 25 Debian packages in
  the report plugin's distroless image, among them GPL-2.0, GPL-3.0 and LGPL packages and the JRE
  (GPL-2.0 with the Classpath Exception).

### Decided by the maintainer (2026-10-30)

Nothing found is incompatible with distribution under Apache-2.0. Two points were decisions rather than
findings; the maintainer made them:

1. **MySQL Connector/J ships as reasoned.** It is GPL-2.0 with Oracle's Universal FOSS Exception, the
   one copyleft licence inside the jar. `NOTICE` records why that is compatible — `runtimeOnly`, reached
   through JDBC, unmodified, the exception listing Apache-2.0 — and the allowlist permits that licence
   for that jar alone, so a second jar under it fails the check. PostgreSQL's driver (BSD-2-Clause)
   would remove the question, but 1.0 supports MySQL only.
2. **The images point to their distributions' sources; no source bundle is published.** Distributing
   an image distributes busybox, coreutils and the JRE in binary form, and the GPL asks the distributor
   to provide their corresponding source. `NOTICE` points to the distributions' source archives
   (Alpine aports, Debian, Adoptium) at the versions the images carry. A source bundle beside the
   images can be added later if a distributor needs one.

The `licences` job is one of the checks the `develop` ruleset requires.
