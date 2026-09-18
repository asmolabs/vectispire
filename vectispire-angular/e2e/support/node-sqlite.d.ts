/**
 * The little of `node:sqlite` the fixture uses.
 *
 * <p><b>Declared here rather than by raising a shared dependency.</b> The module has been built
 * into Node since 22.5, but this repository's `@types/node` does not know it yet; bumping that for
 * a seeding fixture would move the typing of the whole front end for three calls. This surface is
 * deliberately tiny: the day it is no longer enough is the sign that the real dependency is
 * needed.
 */
declare module 'node:sqlite' {
    export class DatabaseSync {
        constructor(path: string);
        prepare(sql: string): {
            run(...params: unknown[]): unknown;
            get(...params: unknown[]): unknown;
        };
        close(): void;
    }
}
