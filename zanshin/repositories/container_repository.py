from sqlalchemy.orm import Session
from zanshin.models.container import Container

class ContainerRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_all(self):
        return self.db.query(Container).all()

    def find_by_id(self, container_id: int):
        return self.db.query(Container).filter(Container.id == container_id).first()

    def find_by_registry_and_image_name_and_tag(self, registry: str, image_name: str, tag: str):
        return self.db.query(Container).filter(
            Container.registry == registry,
            Container.image_name == image_name,
            Container.tag == tag
        ).first()

    def save(self, container: Container) -> Container:
        self.db.add(container)
        self.db.commit()
        self.db.refresh(container)
        return container

    def delete_by_id(self, container_id: int):
        container = self.find_by_id(container_id)
        if container:
            self.db.delete(container)
            self.db.commit()
            return True
        return False
