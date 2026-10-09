# Attack Path View

The attack path view (`AttackPathService`, `/api/v1/attack-paths`) puts side by side, for one
repository, the routes it exposes and the critical vulnerabilities and secrets it carries. **It is a
co-location heuristic, not a reachability analysis**: two findings are linked because they belong to
the same repository, never because anything established that one leads to the other.

Read it as "this repository has an unauthenticated route *and* a critical vulnerability — look at
both together", not as "this vulnerability is exploitable from the Internet".

---

## How the graph is built

For each repository the caller may see:

1. **An `Internet Ingress (0.0.0.0/0)` node.** Synthetic: it is drawn for every repository, whether
   or not the application is deployed, let alone reachable from the Internet. Vectispire knows
   nothing of the network in front of the code.
2. **Exposed routes.** Every route of the API inventory that is declared public or that requires no
   authentication (`authRequired = false`), linked from the ingress node. An unauthenticated route
   whose path contains `admin`, `auth`, `login`, `user`, `payment`, `checkout`, `secret`, `token` or
   `upload` is drawn as critical, any other unauthenticated route as high.
3. **Vulnerable components.** The repository's open, untriaged issues that are critical, high or on
   the CISA KEV list (secrets apart), KEV first then by severity, at most ten. **Every exposed route
   is linked to every one of them** — the product of the two lists. The edge does not mean the route
   calls the component; the API inventory records no call graph, and Vectispire runs no call-graph
   analysis (the issue's `reachability` column reads `UNKNOWN` everywhere and the graph does not read
   it). Without any exposed route, the vulnerabilities are linked to the ingress node directly.
4. **A `Database / Production Data Sink` node**, fixed: drawn for every repository, linked from every
   vulnerability, whether or not the application has a database.
5. **Secrets** found in the repository, at most ten, linked from the first vulnerability or, with
   none, from the ingress node.

A finding triaged *not affected* or *fixed* is left out. The node lists are cut at ten for
legibility; the counts and the score below are computed before the cut.

**"Exploitable" means one thing here:** a vulnerability node is flagged exploitable when the
repository has at least one unauthenticated route — any route, not one shown to reach that
component.

## Scenarios and score

- **Unauthenticated route + critical vulnerability**: when the repository has both, one scenario
  names its first unauthenticated route and its worst vulnerability, ending at the data sink.
- **Plaintext secret**: when the repository carries a secret, one scenario names the file.
- Otherwise a baseline scenario says no such pairing was found.

The risk score (0–100) is
`35 × scenarios + 25 × secrets + 10 × min(3, vulnerabilities) + 5 × min(3, unauthenticated routes)`,
at least 15 when a vulnerability or secret was found and 10 otherwise. It ranks repositories by what they
carry, not by a likelihood of compromise.

## What it cannot tell you

- whether the vulnerable code is loaded or called by any route;
- whether the application is deployed, or reachable from the Internet at all;
- whether a database, or the secret's target system, is reachable from the vulnerable component;
- anything about containers: the view covers repositories only.

Use it to decide what to look at together, then confirm a path by hand before reporting it as one.

## REST API

* `GET /api/v1/attack-paths/repositories/{repoId}`: the graph and scenarios of one repository (404
  for one the caller may not see).
* `GET /api/v1/attack-paths/overview`: the same for every repository the caller may see.
