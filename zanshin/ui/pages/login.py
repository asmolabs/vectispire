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
            
            # A line naming the default account and its password used to sit here, and
            # its absence is the point: printing working credentials on the
            # unauthenticated page of a security console hands them to anyone who reaches
            # the login form, including whoever found the instance by scanning the
            # network. If a deployment still has a default account, the place to say so is
            # the installation guide, once, to the person installing it.
            #
            # The literal is deliberately not quoted above — `tests/test_ui_assets.py`
            # greps this file, and a citation in a comment would satisfy the grep while
            # the page stayed clean, or fail it while the page was fine. Same trap the
            # encryption-key removal hit.

            spacing="6",
            align="center",
            class_name="zs-card zs-card-lg max-w-sm w-full"
        ),
        min_height="100vh",
        # The same canvas as every other screen. This was `bg-slate-1`, one step lighter,
        # so the login page and the application it leads to were subtly different greys —
        # and the card, being white on near-white, had almost no edge.
        class_name="w-full zs-canvas"
    )
