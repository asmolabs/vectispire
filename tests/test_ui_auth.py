"""Tests for the per-event-handler authorization decorators.

These exercise the decorators directly against a stand-in state object rather
than through Reflex's event machinery (which the rest of the UI layer is also
not tested through — see pyproject.toml). Two things matter: the guard runs
before the handler body for every function *kind* Reflex supports, and the
decorated function still looks like the original to introspection, since
that's how Reflex maps event arguments onto parameters.
"""
import asyncio
import inspect

import pytest

from zanshin.ui.auth import requires_admin, requires_login, requires_role


class FakeState:
    """The three attributes the decorators read, from `BaseState`."""

    def __init__(self, logged_in=True, user_role="USER", username="alice"):
        self.logged_in = logged_in
        self.user_role = user_role
        self.username = username
        self.ran = []

    @requires_login
    def plain_handler(self, value="x"):
        self.ran.append(value)
        return "handler-result"

    @requires_login
    def generator_handler(self, value="x"):
        self.ran.append(value)
        yield "yielded-1"
        yield "yielded-2"

    @requires_login
    async def coroutine_handler(self, value="x"):
        self.ran.append(value)
        return "coroutine-result"

    @requires_login
    async def async_generator_handler(self, value="x"):
        self.ran.append(value)
        yield "async-yielded"

    @requires_admin
    def admin_handler(self):
        self.ran.append("admin")
        return "admin-result"

    @requires_role("SUPERUSER")
    def superuser_handler(self):
        self.ran.append("superuser")
        return "superuser-result"


async def _drain(async_gen):
    return [event async for event in async_gen]


def _run(coro):
    """Drive a coroutine to completion without an async test plugin — the
    suite has no async framework dependency (see pyproject.toml)."""
    return asyncio.run(coro)


def test_authenticated_user_reaches_a_plain_handler():
    state = FakeState()
    assert state.plain_handler("v") == "handler-result"
    assert state.ran == ["v"]


def test_anonymous_caller_is_blocked_from_a_plain_handler():
    state = FakeState(logged_in=False)

    result = state.plain_handler()

    assert state.ran == []
    assert result  # a redirect event, not the handler's return value
    assert result != "handler-result"


def test_generator_handler_body_never_runs_for_anonymous_caller():
    """The regression risk of wrapping generators: if the guard returned
    instead of yielding, Reflex would consume nothing and the body would still
    have run on first iteration."""
    state = FakeState(logged_in=False)

    events = list(state.generator_handler())

    assert state.ran == []
    assert len(events) == 1  # the redirect
    assert "yielded-1" not in events


def test_generator_handler_still_yields_everything_when_allowed():
    state = FakeState()
    assert list(state.generator_handler()) == ["yielded-1", "yielded-2"]


def test_coroutine_handler_is_guarded_and_still_awaitable():
    allowed = FakeState()
    assert _run(allowed.coroutine_handler("v")) == "coroutine-result"
    assert allowed.ran == ["v"]

    denied = FakeState(logged_in=False)
    result = _run(denied.coroutine_handler())
    assert denied.ran == []
    assert result != "coroutine-result"


def test_async_generator_handler_is_guarded_and_still_iterable():
    allowed = FakeState()
    assert _run(_drain(allowed.async_generator_handler("v"))) == ["async-yielded"]
    assert allowed.ran == ["v"]

    denied = FakeState(logged_in=False)
    events = _run(_drain(denied.async_generator_handler()))
    assert denied.ran == []
    assert "async-yielded" not in events


def test_plain_user_cannot_reach_an_admin_handler():
    state = FakeState(user_role="USER")

    result = state.admin_handler()

    assert state.ran == []
    assert result != "admin-result"


@pytest.mark.parametrize("role", ["ADMIN", "SUPERUSER"])
def test_admin_and_superuser_reach_an_admin_handler(role):
    state = FakeState(user_role=role)
    assert state.admin_handler() == "admin-result"


def test_an_admin_is_not_automatically_a_superuser():
    state = FakeState(user_role="ADMIN")

    result = state.superuser_handler()

    assert state.ran == []
    assert result != "superuser-result"


def test_authentication_is_checked_before_the_role():
    """An anonymous caller goes to /login rather than being told they lack a
    role — and never reaches the body either way."""
    state = FakeState(logged_in=False, user_role="SUPERUSER")

    assert state.admin_handler() != "admin-result"
    assert state.ran == []


# --- Introspection contract with Reflex ---

def _undecorated(name):
    return getattr(FakeState, name)


@pytest.mark.parametrize(
    "name",
    ["plain_handler", "generator_handler", "coroutine_handler", "async_generator_handler"],
)
def test_decorated_handlers_keep_their_signature(name):
    """Reflex reads handler parameters to decide which event arguments to
    pass. `inspect.signature` follows `__wrapped__`, `getfullargspec` does
    not — both must report the real parameters (hence the explicit
    `__signature__` in `_preserve`)."""
    fn = _undecorated(name)

    assert list(inspect.signature(fn).parameters) == ["self", "value"]
    assert inspect.getfullargspec(fn).args == ["self", "value"]
    assert fn.__name__ == name


def test_decorated_handlers_keep_their_function_kind():
    """Reflex dispatches on the kind of the handler function; a generator
    handler wrapped in a plain function would have its yields dropped."""
    assert inspect.isgeneratorfunction(_undecorated("generator_handler"))
    assert inspect.iscoroutinefunction(_undecorated("coroutine_handler"))
    assert inspect.isasyncgenfunction(_undecorated("async_generator_handler"))
    assert not inspect.isgeneratorfunction(_undecorated("plain_handler"))
