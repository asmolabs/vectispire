/**
 * What is left of timestamp handling: almost nothing, and that is the point.
 *
 * The columns are `timestamptz` and the entities carry `Date`s. There is therefore no more
 * parsing, no canonicalization, no conversion to text — the three functions that used to
 * live here existed only because the database stored timezone-less timestamps, inherited
 * from the SQLAlchemy schema.
 *
 * One rule remains: **when an instant has to be compared byte for byte** — in a fingerprint,
 * in an export — it is written as ISO 8601 UTC to the millisecond, by `canonical()`. That is
 * `Date.prototype.toISOString`, named so the intent is readable at the call site.
 */

/** The present instant. Named rather than written `new Date()` everywhere, so the tests
 *  have a single place to replace the day they need to. */
export function now(): Date {
    return new Date();
}

/**
 * An instant's comparable form: `YYYY-MM-DDTHH:MM:SS.sssZ`.
 *
 * Always UTC and always to the millisecond, whatever the machine's timezone. Two processes
 * in two timezones must produce the same string for the same instant, otherwise a
 * fingerprint computed here does not verify there.
 */
export function canonical(value: Date): string {
    return value.toISOString();
}
