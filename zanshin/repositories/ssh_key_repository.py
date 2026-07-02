import uuid
from sqlalchemy.orm import Session
from zanshin.models.ssh_key import SSHKey

class SSHKeyRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_all(self):
        return self.db.query(SSHKey).all()

    def find_by_id(self, key_id: uuid.UUID):
        # Convert to UUID object if string
        if isinstance(key_id, str):
            key_id = uuid.UUID(key_id)
        return self.db.query(SSHKey).filter(SSHKey.id == key_id).first()

    def find_by_name(self, name: str):
        return self.db.query(SSHKey).filter(SSHKey.name == name).first()

    def save(self, ssh_key: SSHKey) -> SSHKey:
        self.db.add(ssh_key)
        self.db.commit()
        self.db.refresh(ssh_key)
        return ssh_key

    def delete_by_id(self, key_id: uuid.UUID):
        if isinstance(key_id, str):
            key_id = uuid.UUID(key_id)
        ssh_key = self.find_by_id(key_id)
        if ssh_key:
            self.db.delete(ssh_key)
            self.db.commit()
            return True
        return False
