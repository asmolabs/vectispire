-- What each agent's executors can run, as the agent last said.
--
-- A worker whose Docker daemon is down, or whose Kubernetes API refuses its service account, used to claim scans
-- and fail every one of them: an attempt spent per claim, for a fault that was the worker's. An agent now says, in
-- its hello and again whenever it changes, which executors it has, whether each can run anything, and which kinds
-- of target each scans; the claim hands it nothing its available executors cannot run (`WorkerExecutors`).
--
-- `executors` is that list as JSON, `executors_reported_at` when it was last said. Null on every existing row, and
-- on every row an agent older than the announcement writes: null is "unknown", and such an agent claims as it
-- always did (decision 0043 §2).
--
-- Written once, in common: two nullable columns, typed by the placeholders.

alter table t_agent add executors ${text};

alter table t_agent add executors_reported_at ${ts};
