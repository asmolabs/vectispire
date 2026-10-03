-- A build's CycloneDX SBOM, imported by a declared source for a repository (G10, decision 0039).
--
-- Written once, in common: new tables with no foreign key, and columns added to the inventory with no
-- default. The rows naming a repository go with it through the `inventory` module's listener
-- (`TargetDeleted`), as the coverage imports do through `plugins`'; the imports leave by the evidence
-- window as well.

-- One accepted build SBOM: the source and key that sent it, what it declared, and what the pipeline
-- says it describes — `commit_sha` and `branch_name` are the pipeline's word. A stated branch decides
-- which scans the SBOM completes; the commit is kept, and compared with nothing.
create table t_build_sbom (
    id ${id},
    source_id bigint not null,
    source_slug varchar(40) not null,
    repo_id bigint not null,
    spec_version varchar(10) not null,
    tool varchar(200),
    components_count int not null,
    commit_sha varchar(64),
    branch_name varchar(255),
    document_sha256 varchar(64) not null,
    imported_at ${ts} not null,
    imported_by varchar(255) not null,
    api_key_id char(36) not null
);

create index idx_build_sbom_repo on t_build_sbom (repo_id, id);
create index idx_build_sbom_imported on t_build_sbom (imported_at);

-- Each component the build listed, as the inventory's columns hold it: kept so that every later scan of
-- the repository can be completed by the newest SBOM, not only the scan that was newest on arrival.
create table t_build_sbom_component (
    id ${id},
    import_id bigint not null,
    name varchar(255) not null,
    version varchar(255),
    purl varchar(500),
    type varchar(50),
    license varchar(255)
);

create index idx_build_sbom_component_import on t_build_sbom_component (import_id);

-- A scan's inventory row says who listed it. `origin` null is the scanner's — every row written before
-- this, and every row a scan writes; `build` a component only the build listed, `both` a scanner row the
-- build also lists, its version and purl then the build's and the scanner's kept beside them, so that a
-- later SBOM no longer listing the package gives the row back as the scanner wrote it. `declared_license`
-- is the licence the build declared; the scanner's stay in its SBOM. `build_sbom_id` names the import
-- that completed the row, and is a reference only: the import leaves by the evidence window, the
-- inventory a scan was given stays what it was given.
alter table t_component add column origin varchar(10);
alter table t_component add column build_sbom_id bigint;
alter table t_component add column scanned_version varchar(255);
alter table t_component add column scanned_purl varchar(500);
alter table t_component add column declared_license varchar(255);

create index idx_component_build_sbom on t_component (build_sbom_id);
