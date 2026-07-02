from sqlalchemy.orm import Session
from zanshin.models.setting import Setting

class SettingRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_all(self):
        return self.db.query(Setting).all()

    def find_by_key(self, key: str):
        return self.db.query(Setting).filter(Setting.key == key).first()

    def save(self, setting: Setting) -> Setting:
        self.db.add(setting)
        self.db.commit()
        self.db.refresh(setting)
        return setting

    def delete_by_key(self, key: str):
        setting = self.find_by_key(key)
        if setting:
            self.db.delete(setting)
            self.db.commit()
            return True
        return False
