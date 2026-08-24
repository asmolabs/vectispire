create index idx_scan_queue on t_scan(status, required_agent_label, created_at, id);
create index idx_audit_log_order on t_audit_log(timestamp, id);
create unique index uq_semgrep_rule_set_active on t_semgrep_rule_set(is_active);
