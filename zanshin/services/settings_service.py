from typing import Dict
from zanshin.models.setting import Setting
from zanshin.repositories.setting_repository import SettingRepository

class SettingsService:
    def __init__(self, setting_repository: SettingRepository):
        self.setting_repository = setting_repository

    def get_all_settings(self) -> Dict[str, str]:
        settings = self.setting_repository.find_all()
        return {s.key: s.value for s in settings}

    def get_setting(self, key: str, default_value: str = "") -> str:
        s = self.setting_repository.find_by_key(key)
        return s.value if s else default_value

    def update_setting(self, key: str, value: str) -> Setting:
        setting = self.setting_repository.find_by_key(key)
        if not setting:
            setting = Setting(key=key, value=value)
        else:
            setting.value = value
        return self.setting_repository.save(setting)
