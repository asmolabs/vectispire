from zanshin.services.audit_log_service import AuditLogService, AuditOperation


def test_record_persists_an_entry(audit_log_repository):
    svc = AuditLogService(audit_log_repository)

    svc.record(
        AuditOperation.USER_CREATED,
        resource_id="42",
        description="Utilisateur 'bob' créé",
        user_id="admin",
    )

    entries = svc.find_recent()
    assert len(entries) == 1
    assert entries[0].operation_type == "USER_CREATED"
    assert entries[0].resource_id == "42"
    assert entries[0].user_id == "admin"


def test_find_recent_orders_newest_first(audit_log_repository):
    svc = AuditLogService(audit_log_repository)

    svc.record(AuditOperation.LOGIN_SUCCESS, "1", "first")
    svc.record(AuditOperation.LOGIN_SUCCESS, "1", "second")
    svc.record(AuditOperation.LOGIN_SUCCESS, "1", "third")

    entries = svc.find_recent()

    assert [e.description for e in entries] == ["third", "second", "first"]


def test_record_truncates_overly_long_description(audit_log_repository):
    svc = AuditLogService(audit_log_repository)

    svc.record(AuditOperation.SETTING_UPDATED, "x", "a" * 500)

    entry = svc.find_recent()[0]
    assert len(entry.description) == 255


def test_record_never_raises_when_repository_fails():
    class BrokenRepository:
        def save(self, entry):
            raise RuntimeError("disk full (simulated)")

    svc = AuditLogService(BrokenRepository())

    # Must not raise: a broken audit log must never break the action it
    # was supposed to describe.
    svc.record(AuditOperation.SETTING_UPDATED, "scan_backend", "should not raise")


def test_record_user_id_defaults_to_none_for_system_events(audit_log_repository):
    svc = AuditLogService(audit_log_repository)

    svc.record(AuditOperation.LOGIN_FAILURE, resource_id="unknown_user", description="failed login")

    assert svc.find_recent()[0].user_id is None
