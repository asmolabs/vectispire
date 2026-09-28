# API errors

Every refusal of the REST API is an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem
document. Read `detail`: it is the sentence written for whoever made the request.

```json
{
  "title": "Bad Request",
  "status": 400,
  "detail": "Scheme \"ftp\" is not allowed. Expected https, ssh or git.",
  "instance": "/api/v1/repositories"
}
```

| Member | Always there | Meaning |
|---|---|---|
| `status` | yes | The HTTP status, repeated. |
| `title` | yes | The status's standard phrase. Not meant to be shown on its own. |
| `detail` | yes | What went wrong, in words meant to be displayed as they are. |
| `instance` | yes | The path that was requested. |
| `retryAfterSeconds` | on a 429 | How long to wait. The `Retry-After` header carries the same number. |
| `correlationId` | on a 500 | A reference to quote to your administrator; also found in `detail`. |

The content type is `application/problem+json`, including for a request the web server rejects
before the application sees it: a URL the security firewall refuses — `//`, an encoded `..`, a
`;` — and one the servlet container cannot decode, such as a lone `%` or an encoded `/`. Both are
a 400 whose `detail` says which kind of URL was refused; neither is an HTML page, and neither
names the server or its version. One exception remains: a failure thrown before any route is
reached is answered by the error page with the same members, as `application/json` unless the
client asks for `application/problem+json` in `Accept`.

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

`/scim/v2/Users` answers a refused value, and a protected account, in the error schema of
[RFC 7644 §3.12](https://www.rfc-editor.org/rfc/rfc7644#section-3.12), because that is what a
directory client parses. Every other refusal on the SCIM routes is a problem document as above.
