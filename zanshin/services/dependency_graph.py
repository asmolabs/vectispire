"""Which dependencies the project actually asked for.

Every vulnerability arrived with the same amount of information about what to *do*
about it: none. A critical CVE in a package listed in `pyproject.toml` is fixed
this afternoon by bumping one line; the same CVE four levels down, pulled in by
something else, waits on an upstream release and may need a pin, a fork, or a
decision to accept the risk. Ranked identically, they produce a backlog nobody
finishes — and the transitive ones, being the majority, are what buries the
handful that are actionable today.

Syft already answers this and the answer was being thrown away. The SBOM carries
`dependency-of` relationships, and in syft's JSON the *parent* of such a
relationship is the dependency while the *child* is what depends on it. So a
package that never appears as a parent is one nothing else pulled in: a root of
the graph, which is exactly "the project declared this".

Verified against a real scan of this repository: 545 artifacts, 43 roots, and the
roots are the declared dependencies — `fastapi`, `gitpython`, `@radix-ui/themes`,
`esbuild` — while `bun.lock`'s 392 transitive packages fall on the other side.

The important part is what happens when the graph is absent. Some catalogers emit
no `dependency-of` edges at all, and then *every* package looks like a root. That
would label an entire container image "direct dependencies", which is worse than
saying nothing: it is a confident wrong answer on the field meant to decide what
to fix first. So an empty graph yields `None` — unknown — everywhere, and the UI
shows nothing rather than a guess.
"""
import logging
from typing import Any, Dict, Optional, Set

logger = logging.getLogger(__name__)

DEPENDENCY_OF = "dependency-of"


class DependencyDirectness:
    """Answers "did the project declare this package?" for one SBOM.

    Built once per scan and queried per finding, because the graph is global to
    the SBOM while findings arrive one package at a time.
    """

    def __init__(self, sbom: Optional[Dict[str, Any]]):
        self._by_purl: Dict[str, bool] = {}
        self._by_name_version: Dict[tuple, bool] = {}
        self.available = False

        artifacts = (sbom or {}).get("artifacts") or []
        relationships = (sbom or {}).get("artifactRelationships") or []
        if not artifacts:
            return

        depended_upon: Set[str] = {
            rel.get("parent")
            for rel in relationships
            if rel.get("type") == DEPENDENCY_OF and rel.get("parent")
        }
        if not depended_upon:
            logger.info(
                "SBOM carries no dependency relationships — directness left unknown for "
                "%d artifact(s)", len(artifacts),
            )
            return

        self.available = True
        for artifact in artifacts:
            is_direct = artifact.get("id") not in depended_upon
            purl = artifact.get("purl")
            if purl:
                # A purl already carries the version, so two versions of the same
                # package keep separate answers — which matters, because one can be
                # declared and the other dragged in.
                self._by_purl[purl] = self._by_purl.get(purl, False) or is_direct
            name = artifact.get("name")
            if name:
                key = (name, artifact.get("version") or "")
                self._by_name_version[key] = self._by_name_version.get(key, False) or is_direct

        direct_count = sum(1 for v in self._by_purl.values() if v)
        logger.info(
            "Dependency graph: %d of %d packages are direct (declared by the project)",
            direct_count, len(self._by_purl) or len(artifacts),
        )

    def of(
        self,
        purl: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> Optional[bool]:
        """`True` direct, `False` transitive, `None` unknown.

        purl first — it is the ecosystem-qualified identity, and it is what both
        Grype's matches and the licence findings carry. Name+version is the
        fallback for a cataloger that produced no purl; matching on the name alone
        is deliberately not attempted, since two versions of one package can sit on
        opposite sides of this answer.
        """
        if not self.available:
            return None
        if purl and purl in self._by_purl:
            return self._by_purl[purl]
        if name:
            key = (name, version or "")
            if key in self._by_name_version:
                return self._by_name_version[key]
        return None
