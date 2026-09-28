-- The EPSS generation replaced last is kept until the next file is applied.
--
-- A reader reads the generation the sync row names, then that generation's scores, in two
-- statements. When a synchronisation switched generations between the two and deleted the one it
-- replaced straight away, the reader asked for rows that were gone: a scan enriched at that moment
-- got no score for any of its CVE — unknown, where the file in use scored them all — and nothing
-- said so. `epss_previous_generation` names the generation replaced last; it is deleted when the
-- one after is applied, a day later, so a reader that read the row just before a switch finds
-- every row it asks for. It costs one generation's rows, some 380,000, kept a day longer.
--
-- Written once, in common: a nullable column added. Null on every installation until its next
-- synchronisation, which then keeps the generation it replaces.

alter table t_threat_intel_sync add column epss_previous_generation bigint;
