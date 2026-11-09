#!/usr/bin/env python3
"""A vulnerability database for the matcher that knows one advisory, invented for the check.

Usage: matcher-db.py <vulnerability.db> <package> <version bound>

**Why not the real one.** The matcher's database is some 3 GB unpacked (180 MB compressed, in
September 2026): downloaded at every run, it would be most of the check's time and all of its network,
and it would make the check depend on the publisher's day. What `composition-scan-check.sh` is about
is whether the matcher, started by the product through the composition, runs as the workspace's
owner, reads the SBOM and the database it is handed read-only and offline, and answers — not what the
publisher knows this week. So this writes a database the pinned matcher accepts as its own, with one
advisory against a package nobody publishes, and the check asks for exactly that advisory: a match
that could only come from this file, never from a real database somebody's cache happened to hold.

**The schema is the matcher's, copied, not guessed.** Dumped with `sqlite3 .schema` from the
published v6.1.9 database (built 2026-09-28), the one the matcher pinned in `ScannerImages`
(grype 0.116.1) downloads; the tables it reads are all here, empty but for the rows below. When the
pin moves to a matcher of another schema, `grype db import` or the match refuses this file and the
check fails, naming the dependencies step — regenerate the statements from the new database then;
the version in `db_metadata` is the one to move with them.

The file is imported by the matcher itself (`grype db import`), which writes the `import.json` beside
it with the digest it checks: that half is the tool's, not written here by imitation.
"""
import datetime
import json
import sqlite3
import sys

SCHEMA = """
CREATE TABLE `blobs` (`id` integer PRIMARY KEY AUTOINCREMENT,`value` text NOT NULL);
CREATE TABLE `db_metadata` (`build_timestamp` datetime NOT NULL,`model` integer NOT NULL,`revision` integer NOT NULL,`addition` integer NOT NULL);
CREATE TABLE `providers` (`id` text,`version` text,`processor` text,`date_captured` datetime,`input_digest` text,PRIMARY KEY (`id`));
CREATE TABLE `vulnerability_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`name` text NOT NULL,`status` text NOT NULL,`published_date` datetime,`modified_date` datetime,`withdrawn_date` datetime,`provider_id` text NOT NULL,`blob_id` integer,CONSTRAINT `fk_vulnerability_handles_provider` FOREIGN KEY (`provider_id`) REFERENCES `providers`(`id`));
CREATE TABLE `vulnerability_aliases` (`name` text,`alias` text NOT NULL,PRIMARY KEY (`name`,`alias`));
CREATE TABLE `operating_systems` (`id` integer PRIMARY KEY AUTOINCREMENT,`name` text,`release_id` text,`major_version` text,`minor_version` text,`label_version` text,`codename` text,`channel` text,`eol_date` datetime,`eoas_date` datetime);
CREATE TABLE `packages` (`id` integer PRIMARY KEY AUTOINCREMENT,`ecosystem` text,`name` text);
CREATE TABLE `affected_package_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`vulnerability_id` integer NOT NULL,`operating_system_id` integer,`package_id` integer,`blob_id` integer,CONSTRAINT `fk_affected_package_handles_vulnerability` FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerability_handles`(`id`),CONSTRAINT `fk_affected_package_handles_operating_system` FOREIGN KEY (`operating_system_id`) REFERENCES `operating_systems`(`id`),CONSTRAINT `fk_affected_package_handles_package` FOREIGN KEY (`package_id`) REFERENCES `packages`(`id`));
CREATE TABLE `unaffected_package_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`vulnerability_id` integer NOT NULL,`operating_system_id` integer,`package_id` integer,`blob_id` integer,CONSTRAINT `fk_unaffected_package_handles_vulnerability` FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerability_handles`(`id`),CONSTRAINT `fk_unaffected_package_handles_operating_system` FOREIGN KEY (`operating_system_id`) REFERENCES `operating_systems`(`id`),CONSTRAINT `fk_unaffected_package_handles_package` FOREIGN KEY (`package_id`) REFERENCES `packages`(`id`));
CREATE TABLE `operating_system_specifier_overrides` (`alias` text,`version` text,`version_pattern` text,`codename` text,`channel` text,`replacement` text,`replacement_major_version` text,`replacement_minor_version` text,`replacement_label_version` text,`replacement_channel` text,`rolling` numeric,`applicable_client_db_schemas` text,PRIMARY KEY (`alias`,`version`,`version_pattern`,`replacement`,`replacement_major_version`,`replacement_minor_version`,`replacement_label_version`,`replacement_channel`,`rolling`));
CREATE TABLE `cpes` (`id` integer PRIMARY KEY AUTOINCREMENT,`part` text NOT NULL,`vendor` text,`product` text NOT NULL,`edition` text,`language` text,`software_edition` text,`target_hardware` text,`target_software` text,`other` text);
CREATE TABLE `package_cpes` (`cpe_id` integer,`package_id` integer,PRIMARY KEY (`cpe_id`,`package_id`),CONSTRAINT `fk_package_cpes_cpe` FOREIGN KEY (`cpe_id`) REFERENCES `cpes`(`id`),CONSTRAINT `fk_package_cpes_package` FOREIGN KEY (`package_id`) REFERENCES `packages`(`id`));
CREATE TABLE `package_specifier_overrides` (`ecosystem` text,`replacement_ecosystem` text,PRIMARY KEY (`ecosystem`,`replacement_ecosystem`));
CREATE TABLE `architecture_aliases` (`alias` text,`canonical` text NOT NULL,PRIMARY KEY (`alias`));
CREATE TABLE `affected_cpe_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`vulnerability_id` integer NOT NULL,`cpe_id` integer,`blob_id` integer,CONSTRAINT `fk_affected_cpe_handles_vulnerability` FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerability_handles`(`id`),CONSTRAINT `fk_affected_cpe_handles_cpe` FOREIGN KEY (`cpe_id`) REFERENCES `cpes`(`id`));
CREATE TABLE `unaffected_cpe_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`vulnerability_id` integer NOT NULL,`cpe_id` integer,`blob_id` integer,CONSTRAINT `fk_unaffected_cpe_handles_cpe` FOREIGN KEY (`cpe_id`) REFERENCES `cpes`(`id`),CONSTRAINT `fk_unaffected_cpe_handles_vulnerability` FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerability_handles`(`id`));
CREATE TABLE `known_exploited_vulnerability_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`cve` text NOT NULL,`blob_id` integer);
CREATE TABLE `epss_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`cve` text NOT NULL,`epss` real NOT NULL,`percentile` real NOT NULL);
CREATE TABLE `epss_metadata` (`date` datetime NOT NULL);
CREATE TABLE `cwe_handles` (`id` integer PRIMARY KEY AUTOINCREMENT,`cve` text NOT NULL,`cwe` text NOT NULL,`source` text,`type` text);
"""

# The schema version the pinned matcher reads: model 6, revision 1, addition 9.
MODEL, REVISION, ADDITION = 6, 1, 9

ADVISORY = "VSCHECK-2026-0001"


def main(path, package, bound):
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    # Built now: the matcher's age check, left on in the product, refuses a database older than its
    # limit (five days), and this file is written at every run.
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S+00:00")
    db.execute("insert into db_metadata values (?, ?, ?, ?)", (now, MODEL, REVISION, ADDITION))
    db.execute("insert into providers values ('vectispire-scan-check', '1', 'composition-scan-check', ?, null)", (now,))
    db.execute("insert into blobs (id, value) values (1, ?)", (json.dumps({
        "id": ADVISORY,
        "description": "Invented for scripts/composition-scan-check.sh; matches nothing real.",
        "severities": [{"scheme": "CHML", "value": "high", "rank": 0}],
    }),))
    db.execute("insert into blobs (id, value) values (2, ?)", (json.dumps({
        "ranges": [{"version": {"type": "python", "constraint": "<" + bound},
                    "fix": {"version": bound, "state": "fixed"}}],
    }),))
    db.execute("insert into vulnerability_handles (id, name, status, published_date, modified_date, provider_id, blob_id)"
               " values (1, ?, 'active', ?, ?, 'vectispire-scan-check', 1)", (ADVISORY, now, now))
    db.execute("insert into packages (id, ecosystem, name) values (1, 'python', ?)", (package,))
    db.execute("insert into affected_package_handles (id, vulnerability_id, package_id, blob_id) values (1, 1, 1, 2)")
    db.commit()
    db.close()


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__.splitlines()[2])
    main(*sys.argv[1:])
