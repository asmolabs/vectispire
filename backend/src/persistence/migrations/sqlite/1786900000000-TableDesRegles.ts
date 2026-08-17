import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * The table that holds an uploaded Semgrep rule set.
 *
 * Zanshin bundles one rule, and `ZANSHIN_SEMGREP_RULES_DIR` — the other route to coverage —
 * is read by the process that scans. Every remote agent therefore needed the directory on
 * its own filesystem, with no way for the control plane to check that it had it. Two agents,
 * one provisioned and one not, taking turns on the same target made the SAST backlog resolve
 * and reappear with each turn, silently, because the step ran both times.
 *
 * **`files` is one JSON column, not one row per file.** A set is written once and read
 * whole; rows per file would buy a join and a consistency hazard — a fetch landing between
 * two inserts would ship half a rule set, which is the partial coverage this table exists to
 * prevent.
 *
 * **The unique index over `is_active` is how "at most one active" is said portably.** All
 * four engines count `NULL`s as distinct in a unique index, so inactive rows carry `NULL`
 * and the active one carries true. Storing false instead would make the second deactivated
 * set collide with the first.
 */
export class TableDesRegles1786900000000 implements MigrationInterface {
    name = 'TableDesRegles1786900000000';

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "t_semgrep_rule_set" (
            "id" integer PRIMARY KEY AUTOINCREMENT NOT NULL,
            "name" varchar(255) NOT NULL,
            "files" json NOT NULL,
            "content_hash" varchar(64) NOT NULL,
            "rule_count" integer NOT NULL,
            "file_count" integer NOT NULL,
            "size_bytes" bigint NOT NULL,
            "is_active" boolean,
            "uploaded_by" varchar(255),
            "uploaded_at" datetime NOT NULL,
            "activation_note" text
        )`);
        await queryRunner.query(`CREATE UNIQUE INDEX "uq_semgrep_rule_set_active" ON "t_semgrep_rule_set" ("is_active")`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP INDEX "uq_semgrep_rule_set_active"`);
        await queryRunner.query(`DROP TABLE "t_semgrep_rule_set"`);
    }
}
