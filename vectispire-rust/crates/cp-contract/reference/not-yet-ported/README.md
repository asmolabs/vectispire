# The routes of `openapi.json` the Rust control plane does not serve yet

One file per module of the Java control plane — `<module>.txt`, the module whose controller serves the route on the
Java side — each a `ceiling N` line and one `METHOD /path` per route, `#` starting a comment.

**The list only shrinks.** A route that is served is deleted from its module's file in the commit that serves it, and
that file's ceiling is lowered by as many lines in the same commit; a file whose last route leaves is deleted. A route
the document does not list cannot be added, and a file above or below its ceiling fails. Never edited to make a check
pass.

Who reads it (`crates/cp-contract/src/routes.rs`, `src/shrinking.rs`):

- each module's `tests/contract.rs` (`check_module`): none of the module's routes is still listed;
- `cp-app`'s `tests/route_authorization.rs` (`check_partition`): the routes the binary's registry serves and the routes
  listed here are the document, exactly — a route that left the list and that nothing serves, or one served and still
  listed, fails there;
- `cp-contract replay-plan`: a route that has left the list is served, and its recordings are owed a replay
  (`golden/deferred/`);
- `cp-contract summary`: the total, and each file's.

A file per module so that two ports running at once never edit the same file: each removes lines from, and lowers
the ceiling of, its own. When `openapi.json` moves (`refresh.sh`), a new operation is added to its module's file — the
module whose Java controller serves it — with that file's ceiling raised in the same commit, which says why; the
partition check names every operation the files and the registry do not account for.
