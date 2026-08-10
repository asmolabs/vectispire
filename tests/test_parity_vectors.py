"""Les vecteurs que rejoue la pile TypeScript doivent décrire le vrai code Python.

`scripts/generate_parity_vectors.py` porte une copie de `compute_entry_hash`, pour
tourner sans base ni modèles SQLAlchemy. Une copie dérive : ces tests confrontent les
deux implémentations sur les mêmes entrées, et vérifient que les fichiers commités
correspondent à ce que le script produit aujourd'hui.

Sans eux, la suite TypeScript continuerait de passer en reproduisant fidèlement une
formule que Python n'utilise plus — c'est-à-dire le contraire de ce qu'elle prétend
garantir.
"""
import json
from pathlib import Path

import pytest

from zanshin.models.audit_log import AuditLog
from zanshin.services.audit_log_service import compute_entry_hash

from scripts.generate_parity_vectors import (
    AUDIT_CASES,
    OUTPUT_DIR,
    _audit_entry_hash,
    _postgres_rendering,
    build_audit_vectors,
    build_timestamp_vectors,
)


@pytest.mark.parametrize("case", AUDIT_CASES, ids=lambda c: c["label"])
def test_the_generator_copy_agrees_with_the_real_hash(case):
    """La copie du script et `compute_entry_hash` doivent rendre la même empreinte."""
    entry = AuditLog(
        previous_hash=case["previous_hash"],
        timestamp=case["timestamp"],
        operation_type=case["operation_type"],
        resource_id=case["resource_id"],
        user_id=case["user_id"],
        ip_address=case["ip_address"],
        user_agent=case["user_agent"],
        description=case["description"],
    )
    assert _audit_entry_hash(
        case["previous_hash"],
        case["timestamp"],
        case["operation_type"],
        case["resource_id"],
        case["user_id"],
        case["ip_address"],
        case["user_agent"],
        case["description"],
    ) == compute_entry_hash(entry)


def test_the_committed_vectors_match_what_the_script_produces_today():
    """Les fichiers sous `backend/test/vectors/` sont commités parce que la CI
    TypeScript n'a pas d'interpréteur Python. Ce test est ce qui les empêche de
    vieillir en silence après un changement du code Python.

    S'il échoue : `uv run python scripts/generate_parity_vectors.py`, puis relisez le
    diff — une empreinte qui change est un changement de contrat, pas un détail.
    """
    for name, expected in (
        ("audit-hash.json", build_audit_vectors()),
        ("python-timestamp.json", build_timestamp_vectors()),
    ):
        committed = json.loads((OUTPUT_DIR / name).read_text(encoding="utf-8"))
        assert committed == expected, (
            f"{name} ne correspond plus au code Python — régénérez les vecteurs."
        )


def test_the_vectors_directory_is_where_the_typescript_tests_look():
    assert OUTPUT_DIR == Path(__file__).resolve().parent.parent / "backend" / "test" / "vectors"
    assert (OUTPUT_DIR / "audit-hash.json").exists()


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2026-08-10T08:13:58.322451", "2026-08-10 08:13:58.322451"),
        ("2026-08-10T08:13:58", "2026-08-10 08:13:58"),
        # PostgreSQL retire les zéros de queue : 123000 µs revient en « .123 ».
        # C'est le cas qui casse un lecteur naïf, qui y verrait 123 µs.
        ("2026-01-02T03:04:05.123000", "2026-01-02 03:04:05.123"),
        ("2026-03-01T12:00:00.000010", "2026-03-01 12:00:00.00001"),
    ],
)
def test_the_postgres_rendering_matches_what_the_driver_returns(value, expected):
    """Le rendu que les vecteurs annoncent comme « celui de PostgreSQL ».

    Il n'est pas vérifié contre un vrai serveur ici — `tests/test_database_backends.py`
    en démarre un, ce que cette suite ne fait pas — mais il est verrouillé, pour que
    le contrat que lit la suite TypeScript ne change pas par accident.
    """
    from datetime import datetime

    assert _postgres_rendering(datetime.fromisoformat(value)) == expected
