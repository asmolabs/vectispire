-- The KEV feed becomes CISA's catalogue, synchronised and stored, instead of a list typed into the code.
--
-- **What these two tables held is dropped.** Their only writer was the "synchronisation" that upserted
-- ten hard-coded records: KEV flags dated 2024-01-01 whatever the day CISA listed them, EPSS figures no
-- feed published, and a placeholder identifier. Kept, they would go on answering lookups and ranking
-- the fleet as if CISA had said so. The first real synchronisation — at the first maintenance turn
-- after the upgrade, or from the threat intelligence screen — fills the feed from the catalogue and
-- corrects the exploitation flags of the open issues against it, including those the list had set.
--
-- The singleton row is written back as never synchronised, which is what the status now says.
--
-- `kev_catalog_version` and `kev_released_at` are CISA's `catalogVersion` and `dateReleased`: the
-- age of the data, which the date of the sync does not give when a mirror is refreshed rarely.
-- `last_attempt_at` and `last_error` say whether the last attempt worked, and elect one instance
-- for the scheduled one. 500 is `last_error`'s bound, as on the other error columns.
--
-- Written once, in common: nullable columns added, and statements every engine reads alike.

alter table t_threat_intel_sync add column kev_catalog_version varchar(32);
alter table t_threat_intel_sync add column kev_released_at ${ts};
alter table t_threat_intel_sync add column last_attempt_at ${ts};
alter table t_threat_intel_sync add column last_error varchar(500);

delete from t_threat_intel_feed;
delete from t_threat_intel_sync;

insert into t_threat_intel_sync (id, last_synced_at, cve_count, kev_count, status)
values (1, null, 0, 0, 'NEVER_SYNCED');
