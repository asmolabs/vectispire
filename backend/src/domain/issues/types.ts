/**
 * The finding types, and the partition between what blocks and what does not.
 *
 * **`quality` never fails a build.** That is not a setting: a flag would make this sentence
 * a lie the moment somebody unticked it. It is also why this type is excluded from the
 * counters at the top of a screen — on the day SAST goes live, an ordinary repository goes
 * from a few dozen vulnerabilities to a few thousand quality findings, and a counter that
 * mixes them turns that number into noise nobody looks at any more.
 */
export const TYPE_VULNERABILITY = 'vulnerability';
export const TYPE_SECRET = 'secret';
export const TYPE_IAC = 'iac';
export const TYPE_LICENSE = 'license';
export const TYPE_EOL = 'eol';
export const TYPE_SAST = 'sast';
export const TYPE_QUALITY = 'quality';

/** The types that count towards a security posture. `quality` is absent from it, which is
 *  the whole point of this list. */
export const SECURITY_TYPES = [TYPE_VULNERABILITY, TYPE_SECRET, TYPE_IAC, TYPE_LICENSE, TYPE_EOL, TYPE_SAST] as const;
