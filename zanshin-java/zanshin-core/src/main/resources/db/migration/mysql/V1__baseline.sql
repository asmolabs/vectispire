create table t_api_key (
    id char(36) not null primary key,
    name varchar(255) not null,
    key_hash varchar(255) not null,
    prefix varchar(16),
    created_at datetime(6) not null,
    last_used_at datetime(6),
    scopes varchar(255) not null default 'read,scan,export',
    target_kind varchar(20),
    target_id bigint,
    expires_at datetime(6)
);

create table t_agent (
    id char(36) not null primary key,
    name varchar(255) not null,
    description varchar(500),
    kind varchar(20) not null,
    labels varchar(255),
    credentials_mode varchar(20) not null,
    enabled bit(1) not null,
    max_concurrent int,
    api_key_id char(36) references t_api_key(id) on delete set null,
    hostname varchar(255),
    platform varchar(255),
    version varchar(50),
    scanner_engine varchar(50),
    capabilities longtext,
    contract_version varchar(20),
    sealing_public_key varchar(255),
    last_seen_at datetime(6),
    created_at datetime(6) not null
);

create table t_ssh_key (
    id char(36) not null primary key,
    name varchar(255) not null,
    private_key text not null,
    public_key text,
    created_at datetime(6) not null
);

create table t_container (
    id bigint auto_increment primary key,
    registry varchar(255),
    image_name varchar(255) not null,
    tag varchar(255) not null,
    scan_interval_minutes int,
    scan_cron varchar(255),
    required_agent_label varchar(255),
    last_scheduled_scan_at datetime(6)
);

create table t_repository (
    id bigint auto_increment primary key,
    url varchar(255) not null,
    branch varchar(255) not null,
    sub_path varchar(255),
    name varchar(255),
    scan_interval_minutes int,
    scan_cron varchar(255),
    required_agent_label varchar(255),
    last_scheduled_scan_at datetime(6),
    ssh_key_id char(36) references t_ssh_key(id) on delete set null
);

create table t_scan (
    id bigint auto_increment primary key,
    branch varchar(255) not null,
    sub_path varchar(255),
    status varchar(255) not null,
    sbom longtext,
    cves longtext,
    summary longtext,
    duration_ms bigint,
    findings_count int not null default 0,
    new_issues_count int not null default 0,
    resolved_issues_count int not null default 0,
    error text,
    created_at datetime(6) not null,
    version varchar(255),
    project_type varchar(255),
    repo_id bigint references t_repository(id) on delete cascade,
    container_id bigint references t_container(id) on delete cascade,
    required_agent_label varchar(255),
    claimed_by varchar(64),
    claimed_at datetime(6),
    lease_expires_at datetime(6),
    attempts int not null default 0
);

create table t_ai_review_result (
    id bigint auto_increment primary key,
    scan_id bigint not null references t_scan(id) on delete cascade,
    model varchar(255) not null,
    prompt text not null,
    response text,
    status varchar(50) not null,
    error varchar(500),
    created_at datetime(6) not null
);

create table t_audit_log (
    id char(36) not null primary key,
    description varchar(255) not null,
    operation_type varchar(255) not null,
    resource_id varchar(255) not null,
    timestamp datetime(6) not null,
    user_id varchar(255),
    ip_address varchar(64),
    user_agent varchar(255),
    previous_hash varchar(64),
    entry_hash varchar(64)
);

create table t_issue (
    id bigint auto_increment primary key,
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
    is_kev bit(1) not null default b'0',
    cvss_score double,
    cvss_vector varchar(255),
    fix_state varchar(50),
    fix_versions varchar(255),
    link varchar(500),
    description text,
    state varchar(20) not null default 'open',
    first_seen_at datetime(6) not null,
    last_seen_at datetime(6) not null,
    resolved_at datetime(6),
    first_seen_scan_id bigint references t_scan(id) on delete set null,
    last_seen_scan_id bigint references t_scan(id) on delete set null,
    times_seen int not null default 1,
    triage_status varchar(30) not null default 'under_review',
    triage_justification varchar(64),
    triage_comment text,
    triaged_by varchar(255),
    triaged_at datetime(6),
    triage_expires_at datetime(6),
    is_direct_dependency bit(1),
    line int,
    ticket_ref varchar(64),
    ticket_url varchar(500)
);

create table t_finding (
    id bigint auto_increment primary key,
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
    is_kev bit(1) not null,
    created_at datetime(6) not null,
    cvss_score double,
    cvss_vector varchar(255),
    fix_state varchar(50),
    fix_versions varchar(255),
    link varchar(500),
    issue_id bigint references t_issue(id) on delete set null,
    is_direct_dependency bit(1),
    line int,
    description text
);

create table t_gate_policy (
    id bigint auto_increment primary key,
    target_kind varchar(20) not null,
    target_id bigint not null,
    version int not null,
    is_active bit(1),
    fail_on_severity varchar(20),
    fail_on_kev bit(1) not null,
    fixable_only bit(1) not null,
    include_triaged bit(1) not null,
    include_ai_review bit(1) not null,
    note text,
    created_by varchar(255),
    created_at datetime(6) not null
);

create table t_leader_lease (
    name varchar(64) not null primary key,
    holder varchar(64),
    acquired_at datetime(6),
    expires_at datetime(6),
    updated_at datetime(6) not null
);

create table t_login_attempt (
    id char(36) not null primary key,
    counter_key varchar(255) not null,
    occurred_at datetime(6) not null
);

create table t_outbox_message (
    id char(36) not null primary key,
    message_type varchar(50) not null,
    payload longtext not null,
    status varchar(20) not null,
    attempts int not null,
    next_attempt_at datetime(6),
    last_error text,
    created_at datetime(6) not null,
    sent_at datetime(6)
);

create table t_processed_message (
    id bigint auto_increment primary key,
    message_id varchar(64) not null,
    message_type varchar(50) not null,
    agent_id char(36),
    processed_at datetime(6) not null
);

create table t_user (
    id bigint auto_increment primary key,
    username varchar(255) not null unique,
    email varchar(255) unique,
    password varchar(255),
    display_name varchar(255),
    avatar_url varchar(255),
    role varchar(255) not null,
    is_active bit(1) not null,
    github_id varchar(255) unique,
    keycloak_id varchar(255) unique,
    created_at datetime(6) not null,
    updated_at datetime(6) not null,
    must_change_password bit(1) not null
);

create table t_session (
    token varchar(64) not null primary key,
    user_id bigint not null references t_user(id) on delete cascade,
    created_at datetime(6) not null,
    last_seen_at datetime(6) not null,
    expires_at datetime(6) not null,
    user_agent varchar(255),
    ip_address varchar(64)
);

create table t_setting (
    `key` varchar(255) not null primary key,
    value varchar(255)
);

create table t_semgrep_rule_set (
    id bigint auto_increment primary key,
    name varchar(255) not null,
    files longtext not null,
    content_hash varchar(64) not null,
    rule_count int not null,
    file_count int not null,
    size_bytes bigint not null,
    is_active bit(1),
    uploaded_by varchar(255),
    uploaded_at datetime(6) not null,
    activation_note text
);

create table t_user_target (
    user_id bigint not null references t_user(id) on delete cascade,
    target_kind varchar(20) not null,
    target_id bigint not null,
    primary key (user_id, target_kind, target_id)
);
