"""Tests for direct-versus-transitive dependency attribution.

The shapes here are syft-json's, verified against a real scan of this repository
(545 artifacts, 43 roots) rather than invented: the whole feature rests on the
direction of the `dependency-of` relationship, and getting that backwards would
label every leaf a direct dependency while looking entirely plausible.
"""
from zanshin.services.dependency_graph import DependencyDirectness


def _sbom(artifacts, relationships=()):
    return {"artifacts": list(artifacts), "artifactRelationships": list(relationships)}


def _artifact(id_, name, version="1.0.0", ecosystem="pypi"):
    return {
        "id": id_,
        "name": name,
        "version": version,
        "purl": f"pkg:{ecosystem}/{name}@{version}",
    }


def test_a_package_nothing_depends_on_is_direct():
    """Syft's `dependency-of` names the dependency as `parent` and the dependent as
    `child`, so a package that is never a parent is a root of the graph — which is
    what "the project declared this" means."""
    sbom = _sbom(
        [_artifact("a", "fastapi"), _artifact("b", "starlette")],
        [{"parent": "b", "child": "a", "type": "dependency-of"}],
    )

    graph = DependencyDirectness(sbom)

    assert graph.of("pkg:pypi/fastapi@1.0.0") is True
    assert graph.of("pkg:pypi/starlette@1.0.0") is False


def test_a_package_pulled_in_by_several_others_is_still_transitive():
    sbom = _sbom(
        [_artifact("a", "app"), _artifact("b", "lib"), _artifact("c", "glibc")],
        [
            {"parent": "c", "child": "a", "type": "dependency-of"},
            {"parent": "c", "child": "b", "type": "dependency-of"},
            {"parent": "b", "child": "a", "type": "dependency-of"},
        ],
    )

    graph = DependencyDirectness(sbom)

    assert graph.of("pkg:pypi/app@1.0.0") is True
    assert graph.of("pkg:pypi/glibc@1.0.0") is False


def test_a_package_that_is_both_declared_and_pulled_in_counts_as_direct():
    """A package can be declared *and* required by something else. The project asked
    for it, so it is the project's to bump — the resolution has to favour direct or
    the flag would understate what is fixable."""
    sbom = _sbom(
        [_artifact("a", "app"), _artifact("b", "requests"), _artifact("b2", "requests")],
        [{"parent": "b", "child": "a", "type": "dependency-of"}],
    )

    graph = DependencyDirectness(sbom)

    # Both artifacts carry the same purl: one is depended upon, the other is a root.
    assert graph.of("pkg:pypi/requests@1.0.0") is True


def test_an_sbom_without_a_dependency_graph_answers_unknown():
    """The failure mode that matters. With no `dependency-of` edges, every package
    is a root by the graph definition — so a naive implementation would report an
    entire container image as "direct dependencies", a confident wrong answer on the
    field meant to decide what to fix first."""
    sbom = _sbom(
        [_artifact("a", "fastapi"), _artifact("b", "starlette")],
        [{"parent": "a", "child": "b", "type": "contains"}],
    )

    graph = DependencyDirectness(sbom)

    assert graph.available is False
    assert graph.of("pkg:pypi/fastapi@1.0.0") is None
    assert graph.of("pkg:pypi/starlette@1.0.0") is None


def test_an_empty_or_missing_sbom_answers_unknown():
    for sbom in (None, {}, _sbom([])):
        graph = DependencyDirectness(sbom)
        assert graph.of("pkg:pypi/anything@1.0.0") is None


def test_a_package_absent_from_the_sbom_answers_unknown():
    """Not `False`. A finding whose package the SBOM never mentioned is unmatched,
    and treating that as "transitive" would push it down the list on the strength of
    a lookup miss."""
    sbom = _sbom(
        [_artifact("a", "fastapi"), _artifact("b", "starlette")],
        [{"parent": "b", "child": "a", "type": "dependency-of"}],
    )

    graph = DependencyDirectness(sbom)

    assert graph.of("pkg:npm/left-pad@1.0.0") is None


def test_name_and_version_are_the_fallback_when_there_is_no_purl():
    sbom = {
        "artifacts": [
            {"id": "a", "name": "app", "version": "2.0"},
            {"id": "b", "name": "lib", "version": "3.1"},
        ],
        "artifactRelationships": [{"parent": "b", "child": "a", "type": "dependency-of"}],
    }

    graph = DependencyDirectness(sbom)

    assert graph.of(None, "app", "2.0") is True
    assert graph.of(None, "lib", "3.1") is False


def test_the_name_alone_is_not_enough_to_match():
    """Two versions of one package can sit on opposite sides of this answer, so a
    name-only match would answer for the wrong one."""
    sbom = {
        "artifacts": [
            {"id": "a", "name": "app", "version": "2.0"},
            {"id": "b", "name": "lib", "version": "3.1"},
        ],
        "artifactRelationships": [{"parent": "b", "child": "a", "type": "dependency-of"}],
    }

    graph = DependencyDirectness(sbom)

    assert graph.of(None, "lib", "9.9") is None
    assert graph.of(None, "lib", None) is None


def test_the_real_shape_from_a_repository_scan():
    """A slice of what syft actually produced for this repository: a declared
    dependency (`fastapi`), a lock-file package it pulls in (`starlette`), and a
    GitHub Action, which is declared too."""
    sbom = {
        "artifacts": [
            {"id": "f1", "name": "fastapi", "version": "0.115.0",
             "purl": "pkg:pypi/fastapi@0.115.0", "foundBy": "python-package-cataloger"},
            {"id": "s1", "name": "starlette", "version": "0.38.0",
             "purl": "pkg:pypi/starlette@0.38.0", "foundBy": "python-package-cataloger"},
            {"id": "gh", "name": "actions/checkout", "version": "v4",
             "purl": "pkg:github/actions/checkout@v4",
             "foundBy": "github-actions-usage-cataloger"},
        ],
        "artifactRelationships": [
            {"parent": "s1", "child": "f1", "type": "dependency-of"},
            {"parent": "f1", "child": "f1", "type": "evident-by"},
        ],
    }

    graph = DependencyDirectness(sbom)

    assert graph.of("pkg:pypi/fastapi@0.115.0") is True
    assert graph.of("pkg:pypi/starlette@0.38.0") is False
    assert graph.of("pkg:github/actions/checkout@v4") is True
