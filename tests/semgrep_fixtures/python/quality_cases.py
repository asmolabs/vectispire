"""Fixture for the Python quality rules.

Each line that should be flagged carries `# zanshin: <rule-id>`; every other line must
stay silent. `tests/test_semgrep_rules_backends.py` reads those markers and compares them
against what Semgrep actually reports, so a rule that stops matching — or starts matching
one line too many — fails the suite instead of quietly changing what Zanshin reports.

Deliberately not valid production code: it exists to be matched.
"""


def bare_except():
    # Both rules anchor on the `try`, which is where Semgrep reports a multi-line match.
    try:  # zanshin: zanshin-python-bare-except  # zanshin: zanshin-python-except-pass
        pass
    except:  # noqa: E722
        pass


def typed_except_pass():
    try:  # zanshin: zanshin-python-except-pass
        pass
    except ValueError:
        pass


def typed_except_logged():
    try:
        pass
    except ValueError:
        print("ok")


def mutable_list(items=[]):  # zanshin: zanshin-python-mutable-default-argument
    return items


def mutable_dict(options={}):  # zanshin: zanshin-python-mutable-default-argument
    return options


def immutable_default(items=None):
    return items or []


def file_handling(path):
    handle = open(path)  # zanshin: zanshin-python-open-without-context-manager
    handle.close()
    with open(path) as scoped:
        return scoped.read()


def singleton_comparisons(value):
    if value == None:  # zanshin: zanshin-python-comparison-to-singleton  # noqa: E711
        return 1
    if value is None:
        return 2
    if value == True:  # zanshin: zanshin-python-comparison-to-singleton  # noqa: E712
        return 3
    return 4


def validate(value):
    assert value > 0, "value must be positive"  # zanshin: zanshin-python-assert-outside-tests
    return value


def test_something():
    assert validate(1) == 1, "sanity"
