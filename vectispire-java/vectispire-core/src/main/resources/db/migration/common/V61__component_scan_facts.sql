-- A component row carries what its scan was of, and when that scan was created.
--
-- The inventory's reads joined `t_component` to `t_scan` for three facts only: the repository or the
-- image the scan examined, and the instant it was created — the search's order. Each read named
-- `scanning`'s table from `inventory`, a coupling neither Modulith nor ArchUnit sees in a query string
-- (`CrossModuleQueriesTest`), and asking the scans module instead would have meant handing it every
-- scan identifier the inventory holds, one bind parameter each.
--
-- The three are copied because none of them moves: a scan is created for one target at one instant,
-- and nothing writes either again. The copy cannot outlive its scan either — `fk_component_scan`
-- deletes the component with it, on every engine since V19 — so a copied value never describes a scan
-- that is gone, and no read that joined before can now see a row it did not.
--
-- Filled here from `t_scan` for the rows already stored; `ComponentInventory` writes them from then
-- on. No key of their own: the scan's is the one that matters, and the target's deletion reaches the
-- component through it.
--
-- Written once, in common: added nullable columns, one statement each since SQLite adds one column per
-- `alter table`, and an update every engine reads alike.

alter table t_component add column repo_id bigint;
alter table t_component add column container_id bigint;
alter table t_component add column scan_created_at ${ts};

update t_component set
    repo_id = (select s.repo_id from t_scan s where s.id = t_component.scan_id),
    container_id = (select s.container_id from t_scan s where s.id = t_component.scan_id),
    scan_created_at = (select s.created_at from t_scan s where s.id = t_component.scan_id);
