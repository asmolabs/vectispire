/**
 * Le peu de `node:sqlite` que la fixture utilise.
 *
 * <p><b>Déclaré ici plutôt qu'en relevant une dépendance partagée.</b> Le module est intégré à
 * Node depuis la 22.5 mais les typages `@types/node` de ce dépôt ne le connaissent pas encore ;
 * le monter de version pour une fixture d'amorçage ferait bouger le typage de tout le front pour
 * trois appels. Cette surface est volontairement minuscule : si elle ne suffit plus, c'est le
 * signe qu'il faut la vraie dépendance.
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
