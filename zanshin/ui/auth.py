"""Per-event-handler authentication and role checks.

Why this exists: in Reflex, every event handler on a `State` class is
individually addressable by the client over the websocket. A page that checks
`self.logged_in` in its `on_mount` loader therefore protects the *rendering*
of that page, not the handlers behind it — an unauthenticated client can send
`depots_state.delete_repository` (or `settings_state.set_scan_backend`, or
`api_keys_state.create_api_key`) without ever loading the page, and the
handler will run. The sidebar hiding a link is likewise a display decision,
not an authorization one.

So the check belongs on the handler itself. `@requires_login` / `@requires_admin`
are applied to every handler that reads or writes the database; handlers that
only mutate the caller's own view state (opening a dialog, typing in a field)
are left alone, since they expose nothing the caller doesn't already have.

The decorators preserve the *kind* of the function they wrap (plain,
generator, coroutine, async generator) because that is how Reflex decides how
to consume a handler's result — wrapping a generator handler in a plain
function would make Reflex treat the generator object itself as an event and
silently drop everything the handler yields.
"""
import functools
import inspect
import logging
from typing import Callable, Sequence

import reflex as rx

logger = logging.getLogger(__name__)

ADMIN_ROLES = ("SUPERUSER", "ADMIN")


def _denial_events(state, roles: Sequence[str], handler_name: str) -> list:
    """Events to emit instead of running the handler, or `[]` to let it run."""
    if not state.logged_in:
        logger.warning("Denied unauthenticated call to '%s'", handler_name)
        return [rx.redirect("/login")]
    if roles and state.user_role not in roles:
        logger.warning(
            "Denied call to '%s' by '%s' (role %s, requires %s)",
            handler_name, state.username, state.user_role or "none", "/".join(roles),
        )
        return [
            rx.redirect("/dashboard"),
            rx.toast.error("Accès refusé : cette action est réservée aux administrateurs."),
        ]
    return []


def _preserve(wrapper: Callable, fn: Callable) -> Callable:
    """Make the wrapper indistinguishable from `fn` to introspection.

    `functools.wraps` alone is not enough: it sets `__wrapped__`, which
    `inspect.signature` follows but `inspect.getfullargspec` does not — and
    Reflex reads handler parameters to know which event arguments to pass in.
    A wrapper reported as `(self, *args, **kwargs)` would lose the argument
    names of handlers like `delete_key(self, key_id_str)`. Setting
    `__signature__` explicitly makes both APIs agree on the real one.
    """
    functools.update_wrapper(wrapper, fn)
    wrapper.__signature__ = inspect.signature(fn)
    return wrapper


def requires_role(*roles: str) -> Callable:
    """Guard an event handler. With no roles, any authenticated user passes."""

    def decorator(fn: Callable) -> Callable:
        name = getattr(fn, "__qualname__", fn.__name__)

        if inspect.isasyncgenfunction(fn):
            async def async_gen_wrapper(self, *args, **kwargs):
                denied = _denial_events(self, roles, name)
                if denied:
                    for event in denied:
                        yield event
                    return
                async for event in fn(self, *args, **kwargs):
                    yield event
            return _preserve(async_gen_wrapper, fn)

        if inspect.iscoroutinefunction(fn):
            async def async_wrapper(self, *args, **kwargs):
                denied = _denial_events(self, roles, name)
                if denied:
                    return denied
                return await fn(self, *args, **kwargs)
            return _preserve(async_wrapper, fn)

        if inspect.isgeneratorfunction(fn):
            def gen_wrapper(self, *args, **kwargs):
                denied = _denial_events(self, roles, name)
                if denied:
                    yield from denied
                    return
                yield from fn(self, *args, **kwargs)
            return _preserve(gen_wrapper, fn)

        def wrapper(self, *args, **kwargs):
            denied = _denial_events(self, roles, name)
            if denied:
                return denied
            return fn(self, *args, **kwargs)
        return _preserve(wrapper, fn)

    return decorator


def requires_login(fn: Callable) -> Callable:
    """Any authenticated user."""
    return requires_role()(fn)


def requires_admin(fn: Callable) -> Callable:
    """ADMIN or SUPERUSER — matches the "Administration" section of the sidebar."""
    return requires_role(*ADMIN_ROLES)(fn)
