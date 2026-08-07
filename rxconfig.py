import os

import reflex as rx

# Which origins may open the event websocket.
#
# Reflex defaults to "*", which lets any page a user happens to visit open a socket
# to this instance and create server-side state at will. It cannot steal a session
# — the client token is a UUID4 in localStorage, unreadable cross-origin — but
# unbounded state creation is a denial of service, and an origin check costs
# nothing. Set ZANSHIN_ALLOWED_ORIGINS to the deployment's real origin(s).
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "ZANSHIN_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    if origin.strip()
]

config = rx.Config(
    app_name="zanshin",
    cors_allowed_origins=ALLOWED_ORIGINS,
    plugins=[
        rx.plugins.SitemapPlugin(),
        rx.plugins.TailwindV4Plugin(),
        rx.plugins.RadixThemesPlugin(
            # Modelled on the Sakai admin template (sakai.primeng.org), whose look is
            # light surfaces on a slightly darker page, small corners and no chrome.
            #
            # `appearance="light"` is the reference's default and the one the visual
            # language was measured in; the header keeps its toggle, and
            # `assets/theme.css` is written against Radix's `--slate-*` scale so the
            # dark side is the same design rather than an afterthought.
            #
            # `radius="medium"` renders the 6px corners the template uses — "large"
            # was noticeably rounder than the reference.
            theme=rx.theme(
                appearance="light",
                accent_color="cyan",
                radius="medium",
            )
        )
    ]
)
