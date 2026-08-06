import uuid
from typing import List, Optional

from sqlalchemy.orm import Session

from zanshin.models.agent import KIND_BUILTIN, Agent


class AgentRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_all(self) -> List[Agent]:
        """Built-in first, then remotes newest-first.

        The order the agents screen displays: the built-in agent is the one an
        operator reasons about first, because it is the reason the default
        deployment works at all.
        """
        agents = self.db.query(Agent).order_by(Agent.created_at.desc()).all()
        return sorted(agents, key=lambda a: 0 if a.kind == KIND_BUILTIN else 1)

    def find_by_id(self, agent_id) -> Optional[Agent]:
        if isinstance(agent_id, str):
            try:
                agent_id = uuid.UUID(agent_id)
            except ValueError:
                return None
        return self.db.query(Agent).filter(Agent.id == agent_id).first()

    def find_by_name(self, name: str) -> Optional[Agent]:
        return self.db.query(Agent).filter(Agent.name == name).first()

    def find_by_api_key_id(self, api_key_id) -> Optional[Agent]:
        """The agent a credential belongs to — how an authenticated request
        resolves which worker is calling."""
        if isinstance(api_key_id, str):
            try:
                api_key_id = uuid.UUID(api_key_id)
            except ValueError:
                return None
        return self.db.query(Agent).filter(Agent.api_key_id == api_key_id).first()

    def find_by_worker_id(self, worker_id: str) -> Optional[Agent]:
        """Resolve a `Scan.claimed_by` value back to an agent.

        `claimed_by` stores the uuid as hex rather than a foreign key (see
        `Scan.claimed_by`), so this is the lookup that turns provenance into a
        name for display. Returns `None` for a scan claimed by an agent that has
        since been deleted, which is a normal state, not an error.
        """
        if not worker_id:
            return None
        try:
            return self.db.query(Agent).filter(Agent.id == uuid.UUID(hex=worker_id)).first()
        except (ValueError, AttributeError):
            return None

    def find_builtin(self, hostname: str) -> Optional[Agent]:
        """This host's built-in agent.

        Keyed on hostname rather than "the only builtin row": one row per host
        keeps the model honest the day two web instances share a database, even
        though that deployment is not supported yet (ADR-002 étape 1).
        """
        return (
            self.db.query(Agent)
            .filter(Agent.kind == KIND_BUILTIN, Agent.hostname == hostname)
            .first()
        )

    def save(self, agent: Agent) -> Agent:
        self.db.add(agent)
        self.db.commit()
        self.db.refresh(agent)
        return agent

    def delete_by_id(self, agent_id) -> bool:
        agent = self.find_by_id(agent_id)
        if not agent:
            return False
        self.db.delete(agent)
        self.db.commit()
        return True
