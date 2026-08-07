"""What the interface is allowed to load, and what it must not print.

These two rules are here because both were broken in ways nothing could catch. The font
failure was invisible in every test and every screenshot — the layout was correct, only
the typeface was wrong, and it was wrong in the direction of "looks like a plain sans",
which is what a fallback looks like. The credentials line was visible to everyone and
nobody read it.
"""
import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
THEME_CSS = PROJECT_ROOT / "assets" / "theme.css"
FONT_DIR = PROJECT_ROOT / "assets" / "fonts"


def _source(relative: str) -> str:
    return (PROJECT_ROOT / relative).read_text(encoding="utf-8")


def test_no_stylesheet_is_loaded_from_another_origin():
    """A third-party stylesheet cannot work here, so it must not be declared.

    `zanshin/api/security_headers.py` sets `style-src 'self' 'unsafe-inline'`. Any
    `https://` entry in `rx.App(stylesheets=...)` is therefore refused by the browser and
    silently does nothing — which is exactly what happened to the Google Fonts link that
    was supposed to load Lato. The check is on the declaration rather than on the CSP,
    because the CSP is the part that is right.
    """
    source = _source("zanshin/zanshin.py")
    stylesheets = re.search(r"stylesheets=\[(.*?)\]", source, re.S)
    assert stylesheets, "rx.App no longer declares stylesheets — update this test"
    assert "http://" not in stylesheets.group(1)
    assert "https://" not in stylesheets.group(1)


def test_the_typeface_is_present_as_a_file():
    """The `@font-face` rules must point at files that exist.

    A `src: url(...)` naming a missing file fails the same way a blocked one does: the
    browser falls back and says nothing.
    """
    declared = set(re.findall(r'url\("/([^"]+\.woff2)"\)', THEME_CSS.read_text("utf-8")))
    assert declared, "theme.css declares no @font-face src"
    for relative in declared:
        path = PROJECT_ROOT / "assets" / relative
        assert path.is_file(), f"{relative} is declared in theme.css but not present"
        # A woff2 begins with the signature "wOF2". Catches a placeholder or a saved
        # HTML error page, which are both plausible outcomes of fetching a font by URL.
        assert path.read_bytes()[:4] == b"wOF2", f"{relative} is not a woff2 file"


def test_the_typeface_is_handed_to_radix_and_not_only_to_body():
    """`font-family` on `body` reaches almost nothing in this application.

    Every Radix component sets `font-family: var(--default-font-family)` on itself, and
    Radix defines that variable on `.radix-themes`. Measured in the browser before this
    was fixed, both the heading and the body text of the login page still resolved to
    `-apple-system` — so declaring the font on `body` alone left the entire interface on
    the system stack while looking, in the source, as though it had been set.
    """
    css = THEME_CSS.read_text("utf-8")
    assert "--default-font-family:" in css, (
        "theme.css must override Radix's --default-font-family, not just body's "
        "font-family — see this test's docstring"
    )
    # A heading that keeps the system stack while the body text changes is the visible
    # half of the same mistake.
    assert "--heading-font-family:" in css


def test_the_embedded_font_keeps_its_licence():
    """SIL OFL 1.1 requires the licence text to travel with the font."""
    licence = FONT_DIR / "LICENSE.txt"
    assert licence.is_file(), "assets/fonts/LICENSE.txt is missing"
    assert "SIL Open Font License" in licence.read_text("utf-8")


@pytest.mark.parametrize("secret", ["password123", "admin / password"])
def test_the_login_page_does_not_print_working_credentials(secret):
    """The unauthenticated page must not name an account or a password.

    It used to end with "Default credentials: admin / password123" — readable by anyone
    who reached the form, including whoever found the instance by scanning the network.
    """
    assert secret not in _source("zanshin/ui/pages/login.py")
