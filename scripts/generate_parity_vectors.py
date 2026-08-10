#!/usr/bin/env python
"""Génère, depuis l'implémentation Python de référence, les vecteurs que la pile
TypeScript doit reproduire à l'octet près.

Pourquoi ce script plutôt que des valeurs recopiées à la main dans les tests
TypeScript : trois calculs de Zanshin sont des *contrats de données*, pas des
détails d'implémentation.

* **L'empreinte d'un problème** (`build_fingerprint`). Une divergence d'un seul
  octet relance tout le backlog comme « nouveau » et détruit chaque décision de
  triage déjà prise.
* **La chaîne du journal d'audit** (`compute_entry_hash`). Une divergence rend
  `verify_chain()` faux sur tout l'historique écrit par Python — le journal se
  déclarerait falsifié.
* **Le format d'horodatage**. `datetime.isoformat()` entre dans les deux, et il
  ne se comporte comme aucune fonction JavaScript native : il omet la fraction
  quand les microsecondes valent zéro, et l'écrit sur exactement six chiffres
  sinon. `Date.toISOString()` écrit trois chiffres, toujours, et suffixe « Z ».

Recopier les valeurs attendues à la main figerait un instantané ; les générer
depuis le code réel fait que le jour où quelqu'un change l'implémentation Python,
la suite TypeScript le dit.

    uv run python scripts/generate_parity_vectors.py

Écrit `backend/test/vectors/*.json`, à commiter : la CI TypeScript n'a pas
d'interpréteur Python.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "backend" / "test" / "vectors"


def _audit_entry_hash(
    previous_hash, timestamp, operation_type, resource_id, user_id, ip_address, user_agent, description
) -> str:
    """Copie fidèle de `zanshin.services.audit_log_service.compute_entry_hash`.

    Recopiée plutôt qu'importée pour que ce script tourne sans base de données ni
    modèles SQLAlchemy — `compute_entry_hash` prend une instance d'`AuditLog`, dont
    la construction demanderait tout `zanshin.database`. La copie est vérifiée par
    `test_parity_vectors.py`, qui confronte les deux sur les mêmes entrées.
    """
    parts = [
        previous_hash or "",
        timestamp.isoformat() if timestamp else "",
        operation_type or "",
        resource_id or "",
        user_id or "",
        ip_address or "",
        user_agent or "",
        description or "",
    ]
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


AUDIT_CASES = [
    {
        "label": "microsecondes non nulles",
        "previous_hash": None,
        "timestamp": datetime(2026, 8, 10, 8, 13, 58, 322451),
        "operation_type": "LOGIN_SUCCESS",
        "resource_id": "alice",
        "user_id": "alice",
        "ip_address": "10.0.0.4",
        "user_agent": "Mozilla/5.0",
        "description": "Connexion réussie",
    },
    {
        # Le cas que `toISOString()` rate : Python omet complètement la fraction.
        "label": "microsecondes nulles",
        "previous_hash": "a" * 64,
        "timestamp": datetime(2026, 8, 10, 8, 13, 58, 0),
        "operation_type": "USER_CREATED",
        "resource_id": "7",
        "user_id": "admin",
        "ip_address": None,
        "user_agent": None,
        "description": "Utilisateur créé",
    },
    {
        # PostgreSQL rend « .123 » pour 123000 microsecondes ; Python écrit « .123000 ».
        "label": "millisecondes rondes",
        "previous_hash": "b" * 64,
        "timestamp": datetime(2026, 1, 2, 3, 4, 5, 123000),
        "operation_type": "ISSUE_TRIAGED",
        "resource_id": "42",
        "user_id": "bob",
        "ip_address": "::1",
        "user_agent": "curl/8",
        "description": "Triage : not_affected",
    },
    {
        # Champs vides, accents, tiret cadratin et guillemets français : le hachage
        # est fait sur de l'UTF-8, et une erreur d'encodage ne se verrait que là.
        "label": "champs vides et caractères non ASCII",
        "previous_hash": "",
        "timestamp": datetime(1999, 12, 31, 23, 59, 59, 999999),
        "operation_type": "ACCESS_DENIED",
        "resource_id": "",
        "user_id": None,
        "ip_address": "",
        "user_agent": "",
        "description": "Accès refusé — rôle insuffisant « éèàçü »",
    },
    {
        # Le séparateur est un octet NUL précisément pour qu'aucun contenu ne puisse
        # imiter une frontière de champ. Ce cas le prouve.
        "label": "description contenant un octet NUL",
        "previous_hash": "c" * 64,
        "timestamp": datetime(2026, 3, 1, 12, 0, 0, 1),
        "operation_type": "SETTING_UPDATED",
        "resource_id": "sast_enabled",
        "user_id": "admin",
        "ip_address": "192.168.1.1",
        "user_agent": "-",
        "description": "avant\x00après",
    },
]


def build_audit_vectors() -> list[dict]:
    vectors = []
    for case in AUDIT_CASES:
        timestamp: datetime = case["timestamp"]
        vectors.append(
            {
                "label": case["label"],
                "entry": {
                    "previousHash": case["previous_hash"],
                    # Sous la forme que rend `datetime.isoformat()`, qui est
                    # exactement ce qui entre dans le hachage.
                    "timestamp": timestamp.isoformat(),
                    "operationType": case["operation_type"],
                    "resourceId": case["resource_id"],
                    "userId": case["user_id"],
                    "ipAddress": case["ip_address"],
                    "userAgent": case["user_agent"],
                    "description": case["description"],
                },
                # La forme que rend le pilote PostgreSQL pour la même valeur :
                # espace au lieu de « T », fraction sans zéros de queue.
                "postgresRendering": _postgres_rendering(timestamp),
                "expected": _audit_entry_hash(
                    case["previous_hash"],
                    timestamp,
                    case["operation_type"],
                    case["resource_id"],
                    case["user_id"],
                    case["ip_address"],
                    case["user_agent"],
                    case["description"],
                ),
            }
        )
    return vectors


TIMESTAMP_CASES = [
    datetime(2026, 8, 10, 8, 13, 58, 322451),
    datetime(2026, 8, 10, 8, 13, 58, 0),
    datetime(2026, 1, 2, 3, 4, 5, 123000),
    datetime(1999, 12, 31, 23, 59, 59, 999999),
    datetime(2026, 3, 1, 12, 0, 0, 1),
    datetime(2026, 3, 1, 12, 0, 0, 10),
    datetime(2000, 1, 1, 0, 0, 0, 0),
]


def _postgres_rendering(value: datetime) -> str:
    """Ce que rend PostgreSQL pour un `timestamp without time zone` : séparateur
    espace, et fraction débarrassée de ses zéros de queue (« .123 » pour 123000
    microsecondes), absente quand elle est nulle.

    C'est la forme dont part le code TypeScript, et elle diffère de celle qui entre
    dans le hachage — d'où ce champ dans les vecteurs.
    """
    base = value.strftime("%Y-%m-%d %H:%M:%S")
    if not value.microsecond:
        return base
    return f"{base}.{value.microsecond:06d}".rstrip("0")


def build_timestamp_vectors() -> list[dict]:
    """`datetime.isoformat()` pour chaque cas, avec le rendu PostgreSQL correspondant."""
    return [
        {
            "isoformat": value.isoformat(),
            "postgres": _postgres_rendering(value),
            "microsecond": value.microsecond,
        }
        for value in TIMESTAMP_CASES
    ]


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    written = []
    for name, payload in (
        ("audit-hash.json", build_audit_vectors()),
        ("python-timestamp.json", build_timestamp_vectors()),
    ):
        path = OUTPUT_DIR / name
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        written.append(f"{path.relative_to(REPO_ROOT)} ({len(payload)} vecteurs)")
    print("Écrit :\n  " + "\n  ".join(written))


if __name__ == "__main__":
    main()
