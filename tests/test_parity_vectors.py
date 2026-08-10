"""Les vecteurs que rejoue la pile TypeScript doivent décrire le vrai code Python.

`scripts/generate_parity_vectors.py` porte une copie de `build_fingerprint`, pour
tourner sans base ni modèles SQLAlchemy. Une copie dérive : ces tests confrontent les
deux implémentations sur les mêmes entrées, et vérifient que les fichiers commités
correspondent à ce que le script produit aujourd'hui.

Sans eux, la suite TypeScript continuerait de passer en reproduisant fidèlement une
formule que Python n'utilise plus — c'est-à-dire le contraire de ce qu'elle prétend
garantir.

La chaîne d'intégrité du journal d'audit ne figure plus ici : elle est reconstruite
côté TypeScript sur une forme d'horodatage canonique, pour cesser de dépendre du
format de `datetime.isoformat()`.
"""
import json
from pathlib import Path

import pytest

from zanshin.models.issue import build_fingerprint

from scripts.generate_parity_vectors import (
    FINGERPRINT_CASES,
    OUTPUT_DIR,
    _build_fingerprint,
    build_fingerprint_vectors,
    build_export_vectors,
    build_gate_vectors,
)


@pytest.mark.parametrize("case", FINGERPRINT_CASES, ids=lambda c: c["label"])
def test_the_generator_copy_agrees_with_the_real_fingerprint(case):
    """La copie du script et `build_fingerprint` doivent rendre la même empreinte.

    C'est le contrat le plus coûteux à casser du système : une divergence ne lève
    rien, elle fait simplement que plus aucune empreinte calculée ne correspond à
    celles en base — donc tout le backlog est résolu puis recréé à neuf, triage perdu.
    """
    arguments = {key: value for key, value in case.items() if key != "label"}
    assert _build_fingerprint(**arguments) == build_fingerprint(**arguments)


def test_the_committed_vectors_match_what_the_script_produces_today():
    """Les fichiers sous `backend/test/vectors/` sont commités parce que la CI
    TypeScript n'a pas d'interpréteur Python. Ce test est ce qui les empêche de
    vieillir en silence après un changement du code Python.

    S'il échoue : `uv run python scripts/generate_parity_vectors.py`, puis relisez le
    diff — une empreinte qui change est un changement de contrat, pas un détail.
    """
    for name, expected in (
        ("issue-fingerprint.json", build_fingerprint_vectors()),
        ("policy-gate.json", build_gate_vectors()),
        ("exports.json", build_export_vectors()),
    ):
        committed = json.loads((OUTPUT_DIR / name).read_text(encoding="utf-8"))
        assert committed == expected, (
            f"{name} ne correspond plus au code Python — régénérez les vecteurs."
        )


def test_the_vectors_directory_is_where_the_typescript_tests_look():
    assert OUTPUT_DIR == Path(__file__).resolve().parent.parent / "backend" / "test" / "vectors"
    assert (OUTPUT_DIR / "issue-fingerprint.json").exists()
