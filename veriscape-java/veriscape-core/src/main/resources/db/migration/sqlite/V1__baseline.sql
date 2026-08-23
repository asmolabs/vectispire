create table t_api_key (
    id char(36) not null primary key,
    name varchar(255) not null,
    key_hash varchar(255) not null,
    prefix varchar(16),
    created_at numeric not null,
    last_used_at numeric,
    scopes varchar(255) not null default 'read,scan,export',
    target_kind varchar(20),
    target_id bigint,
    expires_at numeric
);

create table t_agent (
    id char(36) not null primary key,
    name varchar(255) not null,
    description varchar(500),
    kind varchar(20) not null,
    labels varchar(255),
    credentials_mode varchar(20) not null,
    enabled boolean not null,
    max_concurrent int,
    api_key_id char(36) references t_api_key(id) on delete set null,
    hostname varchar(255),
    platform varchar(255),
    version varchar(50),
    scanner_engine varchar(50),
    capabilities text,
    contract_version varchar(20),
    sealing_public_key varchar(255),
    last_seen_at numeric,
    created_at numeric not null
);

create table t_ssh_key (
    id char(36) not null primary key,
    name varchar(255) not null,
    private_key text not null,
    public_key text,
    created_at numeric not null
);

create table t_container (
    id integer primary key autoincrement,
    registry varchar(255),
    image_name varchar(255) not null,
    tag varchar(255) not null,
    scan_interval_minutes int,
    scan_cron varchar(255),
    required_agent_label varchar(255),
    last_scheduled_scan_at numeric
);

create table t_repository (
    id integer primary key autoincrement,
    url varchar(255) not null,
    branch varchar(255) not null,
    sub_path varchar(255),
    name varchar(255),
    scan_interval_minutes int,
    scan_cron varchar(255),
    required_agent_label varchar(255),
    last_scheduled_scan_at numeric,
    ssh_key_id char(36) references t_ssh_key(id) on delete set null
);

create table t_scan (
    id integer primary key autoincrement,
    branch varchar(255) not null,
    sub_path varchar(255),
    status varchar(255) not null,
    sbom text,
    cves text,
    summary text,
    duration_ms bigint,
    findings_count int not null default 0,
    new_issues_count int not null default 0,
    resolved_issues_count int not null default 0,
    error text,
    created_at numeric not null,
    version varchar(255),
    project_type varchar(255),
    repo_id bigint references t_repository(id) on delete cascade,
    container_id bigint references t_container(id) on delete cascade,
    required_agent_label varchar(255),
    claimed_by varchar(64),
    claimed_at numeric,
    lease_expires_at numeric,
    attempts int not null default 0
);

create table t_ai_review_result (
    id integer primary key autoincrement,
    scan_id bigint not null references t_scan(id) on delete cascade,
    model varchar(255) not null,
    prompt text not null,
    response text,
    status varchar(50) not null,
    error varchar(500),
    created_at numeric not null
);

create table t_audit_log (
    id char(36) not null primary key,
    description varchar(255) not null,
    operation_type varchar(255) not null,
    resource_id varchar(255) not null,
    timestamp numeric not null,
    user_id varchar(255),
    ip_address varchar(64),
    user_agent varchar(255),
    previous_hash varchar(64),
    entry_hash varchar(64)
);

create table t_issue (
    id integer primary key autoincrement,
    repo_id bigint references t_repository(id) on delete cascade,
    container_id bigint references t_container(id) on delete cascade,
    fingerprint varchar(64) not null,
    type varchar(50) not null,
    identifier varchar(255),
    package_name varchar(255),
    package_version varchar(255),
    purl varchar(255),
    file_path varchar(500),
    source varchar(50),
    severity varchar(50),
    epss_score double,
    is_kev boolean not null default 0,
    cvss_score double,
    cvss_vector varchar(255),
    fix_state varchar(50),
    fix_versions varchar(255),
    link varchar(500),
    description text,
    state varchar(20) not null default 'open',
    first_seen_at numeric not null,
    last_seen_at numeric not null,
    resolved_at numeric,
    first_seen_scan_id bigint references t_scan(id) on delete set null,
    last_seen_scan_id bigint references t_scan(id) on delete set null,
    times_seen int not null default 1,
    triage_status varchar(30) not null default 'under_review',
    triage_justification varchar(64),
    triage_comment text,
    triaged_by varchar(255),
    triaged_at numeric,
    triage_expires_at numeric,
    is_direct_dependency boolean,
    line int,
    ticket_ref varchar(64),
    ticket_url varchar(500)
);

create table t_finding (
    id integer primary key autoincrement,
    scan_id bigint not null references t_scan(id) on delete cascade,
    type varchar(50) not null,
    severity varchar(50),
    identifier varchar(255),
    package_name varchar(255),
    package_version varchar(255),
    purl varchar(255),
    file_path varchar(500),
    source varchar(50) not null,
    epss_score double,
    is_kev boolean not null,
    created_at numeric not null,
    cvss_score double,
    cvss_vector varchar(255),
    fix_state varchar(50),
    fix_versions varchar(255),
    link varchar(500),
    issue_id bigint references t_issue(id) on delete set null,
    is_direct_dependency boolean,
    line int,
    description text
);

create table t_gate_policy (
    id integer primary key autoincrement,
    target_kind varchar(20) not null,
    target_id bigint not null,
    version int not null,
    is_active boolean,
    fail_on_severity varchar(20),
    fail_on_kev boolean not null,
    fixable_only boolean not null,
    include_triaged boolean not null,
    include_ai_review boolean not null,
    note text,
    created_by varchar(255),
    created_at numeric not null
);

create table t_leader_lease (
    name varchar(64) not null primary key,
    holder varchar(64),
    acquired_at numeric,
    expires_at numeric,
    updated_at numeric not null
);

create table t_login_attempt (
    id char(36) not null primary key,
    counter_key varchar(255) not null,
    occurred_at numeric not null
);

create table t_outbox_message (
    id char(36) not null primary key,
    message_type varchar(50) not null,
    payload text not null,
    status varchar(20) not null,
    attempts int not null,
    next_attempt_at numeric,
    last_error text,
    created_at numeric not null,
    sent_at numeric
);

create table t_processed_message (
    id integer primary key autoincrement,
    message_id varchar(64) not null,
    message_type varchar(50) not null,
    agent_id char(36),
    processed_at numeric not null
);

create table t_user (
    id integer primary key autoincrement,
    username varchar(255) not null unique,
    email varchar(255) unique,
    password varchar(255),
    display_name varchar(255),
    avatar_url varchar(255),
    role varchar(255) not null,
    is_active boolean not null,
    github_id varchar(255) unique,
    keycloak_id varchar(255) unique,
    created_at numeric not null,
    updated_at numeric not null,
    must_change_password boolean not null
);

create table t_session (
    token varchar(64) not null primary key,
    user_id bigint not null references t_user(id) on delete cascade,
    created_at numeric not null,
    last_seen_at numeric not null,
    expires_at numeric not null,
    user_agent varchar(255),
    ip_address varchar(64)
);

create table t_setting (
    key varchar(255) not null primary key,
    value varchar(255)
);

create table t_semgrep_rule_set (
    id integer primary key autoincrement,
    name varchar(255) not null,
    files text not null,
    content_hash varchar(64) not null,
    rule_count int not null,
    file_count int not null,
    size_bytes bigint not null,
    is_active boolean,
    uploaded_by varchar(255),
    uploaded_at numeric not null,
    activation_note text
);

create table t_user_target (
    user_id bigint not null references t_user(id) on delete cascade,
    target_kind varchar(20) not null,
    target_id bigint not null,
    primary key (user_id, target_kind, target_id)
);
