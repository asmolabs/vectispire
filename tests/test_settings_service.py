def test_get_setting_returns_default_when_missing(settings_service):
    assert settings_service.get_setting("does_not_exist", "fallback") == "fallback"


def test_update_setting_creates_then_updates(settings_service):
    settings_service.update_setting("scan_backend", "docker")
    assert settings_service.get_setting("scan_backend") == "docker"

    settings_service.update_setting("scan_backend", "osv")
    assert settings_service.get_setting("scan_backend") == "osv"


def test_get_all_settings_returns_key_value_map(settings_service):
    settings_service.update_setting("a", "1")
    settings_service.update_setting("b", "2")

    all_settings = settings_service.get_all_settings()

    assert all_settings["a"] == "1"
    assert all_settings["b"] == "2"
