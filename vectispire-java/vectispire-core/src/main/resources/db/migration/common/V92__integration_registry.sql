-- The integrations' registry — decision 0040, lot I1: which outside systems this installation may talk to,
-- each switched on or off by the platform governor. One row per integration, keyed `<family>.<name>`
-- (`forge.gitlab`, `siem.syslog_tls`, `tracker.jira`); the list itself is the code's
-- (`Integration.all()`, derived from the adapters' enums), so a key nobody knows any more is a row no
-- reader asks for, as in `t_setting`.
--
-- Written once, in common: a new table, no foreign key. Its own table rather than `t_setting` rows because
-- a switch is a governance gesture whose last author and date the screen shows: a setting row carries
-- neither.
--
-- **Every integration that exists today is seeded enabled** (0040 §5): an upgrade and a new installation
-- change nothing until a governor acts. **An integration without a row reads disabled**: the adapters
-- added after this migration — Bitbucket first — arrive switched off, and nothing has to remember to
-- write a row saying so. Never add a later integration to this list: this file is applied, and its
-- checksum is checked on every start. `updated_at` and `updated_by` stay null until a governor changes
-- the row — the seed is nobody's gesture.
create table t_integration (
    integration_key varchar(64) not null primary key,
    enabled ${bool} not null,
    updated_at ${ts},
    updated_by varchar(255)
);

insert into t_integration (integration_key, enabled) values
    ('forge.github', ${true}),
    ('forge.gitlab', ${true}),
    ('siem.webhook', ${true}),
    ('siem.syslog_udp', ${true}),
    ('siem.syslog_tcp', ${true}),
    ('siem.syslog_tls', ${true}),
    ('ai.ollama', ${true}),
    ('ai.openai', ${true}),
    ('notification.webhook', ${true}),
    ('notification.teams', ${true}),
    ('notification.slack', ${true}),
    ('notification.discord', ${true}),
    ('notification.mail', ${true}),
    ('tracker.gitlab', ${true}),
    ('tracker.github', ${true}),
    ('tracker.jira', ${true}),
    ('tracker.servicenow', ${true});
