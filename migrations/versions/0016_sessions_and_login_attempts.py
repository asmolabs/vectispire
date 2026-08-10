"""sessions révocables et tentatives de connexion, en base plutôt qu'en Redis

Deux tables qui remplacent le seul usage restant de Redis, et qui suppriment donc un
composant d'infrastructure entier.

**Pourquoi elles n'existaient pas.** L'interface Reflex gardait l'état
d'authentification dans son état serveur, indexé par un jeton que le navigateur
conservait en `localStorage`. Ce jeton n'expirait jamais de lui-même et `logout()` ne
pouvait pas l'invalider : il n'y avait aucune session révocable, donc aucun moyen de
déconnecter quelqu'un. Les compteurs anti-bourrage, eux, vivaient en mémoire ou dans
Redis (`zanshin/services/counter_store.py`).

**Pourquoi la base et non Redis.** Redis n'était obligatoire que pour partager l'état
serveur de Reflex entre plusieurs instances, et cet état disparaît avec Reflex. Restent
deux choses à stocker, dans un système qui met déjà sa file de scans en base
(décision 0002) et son bail de chef dans une table plutôt que dans un verrou externe.
Les y mettre est cohérent, retire une dépendance d'exploitation à un outil qui audite
les chaînes d'approvisionnement, et fait survivre les sessions à un redémarrage — ce
que ni la mémoire ni un Redis non persistant ne garantissent.

Le coût est une écriture par tentative de connexion et une lecture par requête
authentifiée. À l'échelle de Zanshin c'est négligeable, et les deux tables se purgent
comme `outbox_message` le fait déjà.

**Écrite en Alembic, et c'est le point.** Le schéma appartient aux migrations pendant
toute la coexistence des deux plans de contrôle ; les entités TypeORM le *décrivent* en
`synchronize: false`, et `schema-parity.integration-spec.ts` vérifie qu'elles restent
exactes. Ces deux tables ne font pas exception.

Revision ID: 0016
Revises: 0015
"""
import sqlalchemy as sa
from alembic import op

from zanshin.models.guid import GUID
from zanshin.models.safedatetime import SafeDateTime

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "session",
        # Le jeton lui-même est la clé : 32 octets d'entropie en base64url, opaque, et
        # jamais dérivé de l'utilisateur. Pas un JWT — rien à déchiffrer, rien qui
        # périme mal, et la révocation ne demande pas de liste noire.
        sa.Column("token", sa.String(64), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer,
            # `CASCADE` : supprimer un compte doit fermer ses sessions. Les laisser
            # orphelines laisserait un jeton valide pointer vers un utilisateur qui
            # n'existe plus.
            sa.ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("created_at", SafeDateTime, nullable=False),
        # Rafraîchi à chaque requête : c'est ce qui distingue une session oubliée d'une
        # session active, et donc ce qui permet une expiration pour inactivité en plus
        # de l'expiration absolue.
        sa.Column("last_seen_at", SafeDateTime, nullable=False),
        # L'échéance absolue, calculée à la création. Stockée plutôt que recalculée
        # pour qu'un changement de réglage ne rallonge pas rétroactivement les sessions
        # déjà ouvertes.
        sa.Column("expires_at", SafeDateTime, nullable=False),
        # Ce que le client a annoncé, pour qu'un utilisateur puisse reconnaître ses
        # propres sessions dans une liste et révoquer celle qu'il ne reconnaît pas.
        sa.Column("user_agent", sa.String(255), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
    )
    # La purge balaie sur cette colonne à chaque tick de l'ordonnanceur, et s'attend à
    # ne rien trouver la plupart du temps.
    op.create_index("ix_session_expires_at", "session", ["expires_at"])
    # « Fermer toutes mes sessions » et la suppression en cascade filtrent sur l'usager.
    op.create_index("ix_session_user_id", "session", ["user_id"])

    op.create_table(
        "login_attempt",
        sa.Column("id", GUID, primary_key=True),
        # Deux compteurs indépendants, d'où deux espaces de noms dans une seule table :
        # `login:user:<identifiant>` et `login:client:<jeton client>`. Une table par
        # compteur n'apporterait rien, et la fenêtre glissante se calcule pareil.
        sa.Column("counter_key", sa.String(255), nullable=False),
        sa.Column("occurred_at", SafeDateTime, nullable=False),
    )
    # L'index composite est ce qui rend le comptage sur fenêtre glissante possible sans
    # lire toute la table : la requête est toujours « cette clé, depuis cet instant ».
    op.create_index("ix_login_attempt_key_time", "login_attempt", ["counter_key", "occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_login_attempt_key_time", table_name="login_attempt")
    op.drop_table("login_attempt")
    op.drop_index("ix_session_user_id", table_name="session")
    op.drop_index("ix_session_expires_at", table_name="session")
    op.drop_table("session")
