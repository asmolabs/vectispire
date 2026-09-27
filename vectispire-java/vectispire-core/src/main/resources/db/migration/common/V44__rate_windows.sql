-- A request limit counted across every instance: one row per limited subject and fixed window.
--
-- Written once, in common: a new table with no foreign key. The tracker webhook's ceiling was a
-- bucket per address in each instance's memory, so behind a load balancer of three instances an
-- address had three ceilings. The key names the limit, the window's number and a digest of the
-- subject (an address is never stored); `hits` is incremented by one conditional statement, the
-- first hit of a window is an insert the primary key arbitrates, and `expires_at` is what the
-- hourly purge reads.
create table t_rate_window (
    window_key varchar(120) not null primary key,
    hits int not null,
    expires_at ${ts} not null
);

create index idx_rate_window_expires on t_rate_window (expires_at);
