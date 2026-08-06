import reflex as rx
from zanshin.ui.state import LoginState

def login_page() -> rx.Component:
    """The Zanshin Login page."""
    return rx.center(
        rx.vstack(
            # Heading & Subheading
            rx.vstack(
                rx.icon(tag="shield-check", size=48, color="var(--accent-9)"),
                rx.heading("Bienvenue sur Zanshin", size="7", weight="bold"),
                rx.text(
                    "Connectez-vous pour accéder au centre de cybersécurité",
                    size="2",
                    color="var(--slate-10)",
                    align="center"
                ),
                align="center",
                spacing="2"
            ),
            
            # Form Section
            rx.form.root(
                rx.vstack(
                    rx.form.field(
                        rx.form.label("Nom d'utilisateur"),
                        rx.input(
                            name="username",
                            placeholder="Entrez votre nom d'utilisateur",
                            required=True,
                            class_name="w-full"
                        ),
                        width="100%"
                    ),
                    
                    rx.form.field(
                        rx.form.label("Mot de passe"),
                        rx.input(
                            type="password",
                            name="password",
                            placeholder="••••••••",
                            required=True,
                            class_name="w-full"
                        ),
                        width="100%"
                    ),
                    
                    rx.button(
                        "Se connecter",
                        loading=LoginState.loading,
                        type="submit",  # Trigger submit on click or Enter
                        class_name="w-full mt-4",
                        size="3",
                        color_scheme="cyan",
                        variant="solid"
                    ),
                    
                    width="100%",
                    spacing="4"
                ),
                on_submit=LoginState.handle_login,
                width="100%"
            ),
            
            # Footer / Links
            rx.text(
                "Default credentials: admin / password123",
                size="1",
                color="var(--slate-9)"
            ),
            
            spacing="6",
            align="center",
            class_name="p-8 rounded-xl bg-slate-2 border border-slate-4 max-w-sm w-full shadow-lg"
        ),
        min_height="100vh",
        class_name="w-full bg-slate-1"
    )
