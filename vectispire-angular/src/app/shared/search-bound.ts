/**
 * The longest free-text search a list route accepts: `BoundedText.SEARCH_MAX` on the server, published as
 * the `maxLength` of each search parameter in `openapi.json` — the backlog's `search`, the audit log's, the
 * inventory's component `name` and the blast radius's `q`.
 *
 * Every search box carries it as its `maxlength`, so the box stops taking characters where the server would
 * stop answering: past it the route refuses the request with a 400, which a reader typing a search would
 * otherwise meet as an error in place of their results. The spec beside this file reads the figure back
 * from the contract, so the two cannot part without a red test.
 */
export const SEARCH_MAX_LENGTH = 500;
