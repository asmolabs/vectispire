alter table t_finding add column reachability varchar(16) not null default 'UNKNOWN';
alter table t_finding add column reachable_symbols text;

alter table t_issue add column reachability varchar(16) not null default 'UNKNOWN';
alter table t_issue add column reachable_symbols text;
