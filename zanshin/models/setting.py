from sqlalchemy import Column, String
from zanshin.database import Base

class Setting(Base):
    __tablename__ = "setting"

    key = Column(String(255), primary_key=True)
    value = Column(String(255), nullable=True)
