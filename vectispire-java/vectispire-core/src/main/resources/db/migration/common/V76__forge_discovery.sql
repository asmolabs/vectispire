-- Forge discoveries and their snapshot — decision 0037 §3, lot D3: a connection's repositories listed in the
-- background, run to run, and compared.
--
-- Written once, in common: new tables, no foreign key in or out. Both belong to the `forges` module, which
-- deletes a connection's discoveries and snapshot with the connection, in one transaction.

-- One discovery. `state` is pending, running, completed, partial or failed; `reason` the closed word of a
-- partial or failed one, `detail` its sentence. `active_key` is the connection's id while the run is pending or
-- running and null once it ended: unique, so a second request for the same connection is answered with the
-- running one rather than listing the organisation twice — both engines admit any number of nulls in a unique
-- index. `claimed_by` and `lease_expires_at` are the queue's, as for a scan: the take is a conditional update,
-- the run renews its lease as it goes, and a lease that lapses puts the run back to pending — a restart resumes
-- a discovery rather than losing it — until `attempts` reaches three. The counters are the progress a screen
-- polls; `new_count`, `changed_count` and `gone_count` the comparison, written when the run ends;
-- `rate_limit_reset_at` when a limit that ended the run partial lifts.
create table t_forge_discovery (
    id ${id},
    connection_id char(36) not null,
    state varchar(20) not null,
    reason varchar(40),
    detail varchar(2000),
    active_key varchar(36),
    requested_at ${ts} not null,
    requested_by varchar(255) not null,
    claimed_by varchar(100),
    lease_expires_at ${ts},
    attempts integer not null,
    started_at ${ts},
    finished_at ${ts},
    namespaces_seen integer not null,
    repositories_seen integer not null,
    repositories_skipped integer not null,
    requests_made integer not null,
    rate_limit_wait_seconds bigint not null,
    rate_limit_reset_at ${ts},
    new_count integer,
    changed_count integer,
    gone_count integer,
    constraint uq_forge_discovery_active unique (active_key)
);

create index idx_forge_discovery_state on t_forge_discovery (state, requested_at);
create index idx_forge_discovery_connection on t_forge_discovery (connection_id, requested_at);

-- The snapshot: one row per repository the connection has ever listed, keyed by the forge's own id, which a
-- rename or a move keeps. Every metadata column is null when the forge did not give the value — unknown is not
-- zero (0007): no size without a Reporter, no language without its request, no default branch for an empty
-- repository. `first_seen_by` and `last_seen_by` name discoveries; `changed_by` the last one that saw a rename, a
-- move, a new default branch or an archival, `change_summary` what; `gone_by` the completed discovery that no
-- longer listed it — only a completed one marks a repository gone, and nothing is ever deleted from here but
-- with the connection.
create table t_forge_repository (
    id ${id},
    connection_id char(36) not null,
    forge_id varchar(64) not null,
    full_path varchar(1000) not null,
    namespace_path varchar(1000) not null,
    personal ${bool} not null,
    name varchar(255) not null,
    default_branch varchar(255),
    archived ${bool},
    fork ${bool},
    visibility varchar(20),
    last_activity_at ${ts},
    language varchar(100),
    size_bytes bigint,
    http_url varchar(1024),
    ssh_url varchar(1024),
    web_url varchar(1024),
    first_seen_by bigint not null,
    first_seen_at ${ts} not null,
    last_seen_by bigint not null,
    last_seen_at ${ts} not null,
    changed_by bigint,
    change_summary varchar(1500),
    gone_by bigint,
    gone_at ${ts},
    constraint uq_forge_repository unique (connection_id, forge_id)
);

create index idx_forge_repository_seen on t_forge_repository (connection_id, last_seen_by);
