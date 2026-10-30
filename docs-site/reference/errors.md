# API errors

Every refusal of the REST API is an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem
document. Read `detail`: it is the sentence written for whoever made the request; branch on `code`.

```json
{
  "title": "Bad Request",
  "status": 400,
  "detail": "Scheme \"ftp\" is not allowed. Expected https, ssh or git.",
  "instance": "/api/v1/repositories",
  "code": "invalid-request"
}
```

| Member | Always there | Meaning |
|---|---|---|
| `status` | yes | The HTTP status, repeated. |
| `title` | yes | The status's standard phrase. Not meant to be shown on its own. |
| `detail` | yes | What went wrong, in words meant to be displayed as they are. |
| `instance` | yes | The path that was requested. |
| `code` | yes | What the refusal is, as a stable token a program branches on — see [the codes](#the-codes). |
| `retryAfterSeconds` | on a 429 | How long to wait. The `Retry-After` header carries the same number. |
| `correlationId` | on a 500 | A reference to quote to your administrator; also found in `detail`. |

The content type is `application/problem+json`, including for a request the web server rejects
before the application sees it: a URL the security firewall refuses — `//`, an encoded `..`, a
`;` — and one the servlet container cannot decode, such as a lone `%` or an encoded `/`. Both are
a 400 whose `detail` says which kind of URL was refused; neither is an HTML page, and neither
names the server or its version. One exception remains: a failure thrown before any route is
reached is answered by the error page with the same members, as `application/json` unless the
client asks for `application/problem+json` in `Accept`.

## The codes

`code` names the kind of refusal for a program, so that a script branches on a token rather than on
the wording of `detail`, which is written for a person and changes with it. It was added on the way
to 1.0 (decision 0043 §6); `status`, `title`, `detail` and `type` are as they were.

| `code` | Status | When |
|---|---|---|
| `invalid-request` | 400 | The request is malformed or a value in it is refused. |
| `authentication-required` | 401 | No credential, or one that is not valid. |
| `forbidden` | 403 | The credential may not do this. |
| `credential-not-accepted` | 403 | An API key or an agent credential on a route that does not take one. |
| `password-change-required` | 403 | The account owes a password change first. |
| `import-refused` | 403 | A SARIF, coverage or test report from a source not declared for it. |
| `not-found` | 404 | What the path names is absent — or hidden from you; the code does not tell the two apart either. |
| `no-such-route` | 404 | Nothing is served at this path: the URL is wrong, not the target gone. |
| `method-not-allowed`, `not-acceptable`, `unsupported-media-type` | 405, 406, 415 | Wrong method, `Accept` or body media type. |
| `conflict` | 409 | The state refuses it, for a reason with no code of its own. |
| `already-queued`, `not-attestable`, `solution-not-empty`, `plugin-conflict` | 409 | A scan already queued; a scan with nothing to attest; a solution still holding projects; a plugin's state. |
| *the cause* | 409 | A conflict a client must tell apart: the code is the last segment of its `urn:vectispire:problem:` `type`, such as `target-already-registered`. |
| `encryption-key-missing`, `credential-withheld` | 412 | The deployment is missing something an operator sets. |
| `content-too-large` | 413 | The body is over the route's ceiling. |
| `unsafe-url` | 422 | A destination refused by the outbound policy. |
| `rate-limited` | 429 | Too many attempts; wait `retryAfterSeconds`. |
| `unexpected-failure` | 500 | A failure nobody wrote a sentence for; quote the `correlationId`. |
| `unavailable` | 502–504 | Transient. |

Codes are open, as enum values are: a client meeting one it does not know falls back on `status`. A
status this table does not name reads `http-<status>`.

The interface shows a refusal in its own language from `code`, and the English `detail` as it is for a
code it does not know. Where `detail` carries the fact that matters — the value an `invalid-request`
refused, the ceiling of a `content-too-large` — the translated sentence quotes it.

## What each status means

| Status | When |
|---|---|
| **400** | The request is malformed or a value in it is refused: a field missing, a URL with a scheme that is not allowed, a parameter of the wrong type, a body that is not JSON. Correct it and send it again. |
| **401** | No credential, or one that is not valid. Sign in again, or check the key. |
| **403** | The credential is valid and may not do this: the role does not allow it, a password change is owed, or the key or agent credential is not accepted on this route. The detail does not name the roles that would be. |
| **404** | The route does not exist, or what the path names does not — **or it exists and you may not see it**. The two read the same, in the same words, on purpose: a different answer would confirm that a repository, a scan or an issue you were not given exists. |
| **405 / 406 / 415** | Wrong method, an `Accept` the route cannot answer, a body in a media type the route does not read. |
| **409** | The request conflicts with the current state and may succeed later unchanged: a scan already queued, a solution that still holds projects, an OWASP review that cannot run yet. |
| **412** | The deployment is missing something an operator sets: the encryption key, a credential an agent cannot receive. |
| **413** | The body is larger than the route accepts. The detail names the ceiling. |
| **422** | A destination refused by the outbound policy. |
| **429** | Too many attempts from this address or with this key. Wait `retryAfterSeconds`. |
| **500** | A failure nobody wrote a sentence for. The detail says only that it happened and quotes a `correlationId`; the full error is in the control plane's log under that reference. |
| **503** | Transient: too many sign-ins awaiting their second factor. Try again in a few minutes. |

## A 500 never explains itself

A 500 does not carry the message of what failed. That message was not written for a client — it
may name a table, a column, a file on the host or a library's internals — so it stays in the log.
To investigate, search the control plane's log for the `correlationId`:

```text
ERROR … Unexpected failure 6f1c2a9e-… on PATCH /api/v1/users/12
```

## SCIM

`/scim/v2/Users` and `/scim/v2/Groups` answer a refused value, a protected account, an absent user
or group (`404`) and a taken `userName` or `displayName` (`409`, `scimType` `uniqueness`) in the error
schema of [RFC 7644 §3.12](https://www.rfc-editor.org/rfc/rfc7644#section-3.12), because that is what a
directory client parses; a filter it does not evaluate is `400` with `scimType` `invalidFilter`. Every
other refusal on the SCIM routes — the token's, a body that is not JSON, a `startIndex` or `count` that
is not a number — is a problem document as above.
