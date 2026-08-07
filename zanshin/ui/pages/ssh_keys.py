import reflex as rx
from typing import List, Dict, Any
from datetime import datetime
import uuid

from zanshin.ui.state import BaseState
from zanshin.ui.auth import requires_login
from zanshin.ui.view_models import SshKeyRow, format_datetime
from zanshin.ui.layout import main_layout
from zanshin.container import get_container
from zanshin.models.ssh_key import SSHKey

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def _truncate(value: str, limit: int = 35) -> str:
    return value[:limit] + "..." if len(value) > limit else value


def _encryption_badge(state) -> rx.Component:
    """Which encryption key this key's private half is still under.

    Worth a column rather than a log line: a key readable only under a previous key
    has not finished being rotated, and one that reads under *no* configured key will
    fail the next clone that needs it — at scan time, in a worker thread, hours later.
    """
    return rx.match(
        state,
        (
            "previous_key",
            rx.tooltip(
                rx.badge("À faire tourner", color_scheme="amber", variant="soft"),
                content=(
                    "Cette clé est chiffrée avec une clé de chiffrement précédente. "
                    "Réenregistrez-la pour la passer sous ENCRYPTION_KEY — et si elle "
                    "date de la clé par défaut publiée dans le dépôt, sa moitié privée "
                    "est publique : générez une nouvelle paire."
                ),
            ),
        ),
        (
            "unreadable",
            rx.tooltip(
                rx.badge("Illisible", color_scheme="red", variant="soft"),
                content=(
                    "Aucune clé configurée ne déchiffre cette valeur : le prochain clone "
                    "qui en a besoin échouera. Renseignez la clé précédente dans "
                    "ZANSHIN_PREVIOUS_ENCRYPTION_KEYS, ou remplacez cette clé SSH."
                ),
            ),
        ),
        rx.badge("OK", color_scheme="green", variant="soft"),
    )


class SSHKeysState(BaseState):
    """Handles loading, adding, generating and deleting SSH Keys."""
    
    keys: list[SshKeyRow] = []
    
    dialog_open: bool = False
    new_name: str = ""
    new_private_key: str = ""
    new_public_key: str = ""

    def set_new_name(self, val: str):
        self.new_name = val

    def set_new_private_key(self, val: str):
        self.new_private_key = val

    def set_new_public_key(self, val: str):
        self.new_public_key = val

    @requires_login
    def load_keys_data(self):
        self.set_current_page("Clés SSH")
        container = get_container()
        try:
            db_keys = container.ssh_key_repository.find_all()
            service = container.ssh_key_service
            self.keys = [
                SshKeyRow(
                    id=str(k.id),
                    name=k.name,
                    public_key=_truncate(k.public_key or "N/A"),
                    created_at=format_datetime(k.created_at),
                    secret_state=service.state_of(k).value,
                )
                for k in db_keys
            ]
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def toggle_dialog(self):
        self.dialog_open = not self.dialog_open

    @requires_login
    def generate_keypair(self):
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode("utf-8")
            
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            ).decode("utf-8")
            
            self.new_private_key = private_pem
            self.new_public_key = public_pem
            yield self.trigger_toast("Paire de clés générée avec succès")
        except Exception as e:
            yield self.trigger_toast(f"Erreur de génération : {str(e)}", is_error=True)

    @requires_login
    def add_ssh_key(self):
        if not self.new_name or not self.new_private_key:
            yield self.trigger_toast("Nom et clé privée requis", is_error=True)
            return

        container = get_container()
        try:
            # Through the service, not the repository: the private half is
            # encrypted *bound to its own row* there (see private_key_context), and
            # doing it here would produce a ciphertext valid in any row.
            container.ssh_key_service.create_key(
                name=self.new_name,
                private_key=self.new_private_key,
                public_key=self.new_public_key,
            )
            
            # Reset inputs
            self.new_name = ""
            self.new_private_key = ""
            self.new_public_key = ""
            self.dialog_open = False
            
            yield self.trigger_toast("Clé SSH ajoutée avec succès")
            yield SSHKeysState.load_keys_data(self)
        except Exception as e:
            yield self.trigger_toast(f"Erreur de sauvegarde : {str(e)}", is_error=True)
        finally:
            container.db.close()

    @requires_login
    def delete_key(self, key_id_str: str):
        container = get_container()
        try:
            key_uuid = uuid.UUID(key_id_str)
            container.ssh_key_repository.delete_by_id(key_uuid)
            yield self.trigger_toast("Clé SSH supprimée")
            yield SSHKeysState.load_keys_data(self)
        except Exception as e:
            yield self.trigger_toast(f"Erreur de suppression : {str(e)}", is_error=True)
        finally:
            container.db.close()

def ssh_keys_page() -> rx.Component:
    """SSH key pair listing and creation view."""
    content = rx.vstack(
        # Page header controls
        rx.hstack(
            rx.text("Gérez les clés de déploiement pour accéder aux dépôts privés", size="2", color="var(--slate-10)"),
            rx.spacer(),
            # Add key dialog
            rx.dialog.root(
                rx.dialog.trigger(
                    rx.button("Ajouter une clé", rx.icon(tag="plus"), color_scheme="cyan")
                ),
                rx.dialog.content(
                    rx.dialog.title("Ajouter une clé SSH"),
                    rx.dialog.description("Créez ou générez une paire de clés d'accès SSH."),
                    rx.vstack(
                        rx.vstack(
                            rx.text("Nom de la clé", size="2", weight="bold"),
                            rx.input(placeholder="Ex: Production Deploy Key", value=SSHKeysState.new_name, on_change=SSHKeysState.set_new_name, required=True, class_name="w-full"),
                            width="100%", spacing="1"
                        ),
                        
                        rx.button("Générer une paire de clés", rx.icon(tag="key"), color_scheme="green", on_click=SSHKeysState.generate_keypair),
                        
                        rx.vstack(
                            rx.text("Clé Privée (format PEM)", size="2", weight="bold"),
                            rx.text_area(placeholder="-----BEGIN RSA PRIVATE KEY-----...", value=SSHKeysState.new_private_key, on_change=SSHKeysState.set_new_private_key, class_name="w-full h-40"),
                            width="100%", spacing="1"
                        ),
                        rx.vstack(
                            rx.text("Clé Publique", size="2", weight="bold"),
                            rx.text_area(placeholder="ssh-rsa AAAAB3NzaC1yc2E...", value=SSHKeysState.new_public_key, on_change=SSHKeysState.set_new_public_key, class_name="w-full h-20"),
                            width="100%", spacing="1"
                        ),
                        spacing="3",
                        class_name="mt-4 w-full"
                    ),
                    rx.hstack(
                        rx.dialog.close(
                            rx.button("Annuler", variant="soft", color_scheme="gray")
                        ),
                        rx.dialog.close(
                            rx.button("Enregistrer", on_click=SSHKeysState.add_ssh_key, color_scheme="green")
                        ),
                        spacing="3",
                        class_name="mt-6 justify-end"
                    ),
                    class_name="max-w-xl w-full"
                )
            ),
            width="100%",
            align="center"
        ),
        
        # Grid/Table
        rx.box(
            rx.table.root(
                rx.table.header(
                    rx.table.row(
                        rx.table.column_header_cell("Nom"),
                        rx.table.column_header_cell("ID / Référence"),
                        rx.table.column_header_cell("Clé Publique"),
                        rx.table.column_header_cell("Chiffrement"),
                        rx.table.column_header_cell("Créée le"),
                        rx.table.column_header_cell("Actions")
                    )
                ),
                rx.table.body(
                    rx.foreach(
                        SSHKeysState.keys,
                        lambda k: rx.table.row(
                            rx.table.row_header_cell(k.name),
                            rx.table.cell(k.id),
                            rx.table.cell(k.public_key),
                            rx.table.cell(_encryption_badge(k.secret_state)),
                            rx.table.cell(k.created_at),
                            rx.table.cell(
                                rx.tooltip(
                                    rx.button(
                                        rx.icon(tag="trash"),
                                        size="2",
                                        color_scheme="red",
                                        variant="soft",
                                        on_click=lambda: SSHKeysState.delete_key(k.id)
                                    ),
                                    content="Supprimer"
                                )
                            )
                        )
                    )
                ),
                width="100%"
            ),
            width="100%",
            class_name="zs-card w-full"
        ),
        
        width="100%",
        spacing="4",
        on_mount=SSHKeysState.load_keys_data
    )
    
    return main_layout(content, "Clés SSH")
