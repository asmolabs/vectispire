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


FINGERPRINT_CASES = [
    {
        "label": "vulnérabilité sur un dépôt, identifiée par purl",
        "repo_id": 3,
        "container_id": None,
        "finding_type": "vulnerability",
        "identifier": "CVE-2024-1234",
        "purl": "pkg:pypi/requests@2.31.0",
        "package_name": "requests",
        "file_path": "requirements.txt",
    },
    {
        # Le purl prime sur le nom : c'est l'identité qualifiée par écosystème.
        "label": "le purl prime sur le nom de paquet",
        "repo_id": 3,
        "container_id": None,
        "finding_type": "vulnerability",
        "identifier": "CVE-2024-1234",
        "purl": "pkg:npm/lodash@4.17.20",
        "package_name": "un-autre-nom",
        "file_path": "package-lock.json",
    },
    {
        # Sans purl (secrets, IaC, licences), le nom prend le relais.
        "label": "repli sur le nom de paquet quand il n'y a pas de purl",
        "repo_id": 3,
        "container_id": None,
        "finding_type": "license",
        "identifier": "GPL-3.0",
        "purl": None,
        "package_name": "quelque-lib",
        "file_path": None,
    },
    {
        "label": "cible conteneur",
        "repo_id": None,
        "container_id": 7,
        "finding_type": "vulnerability",
        "identifier": "CVE-2024-1234",
        "purl": "pkg:deb/debian/openssl@3.0.11",
        "package_name": "openssl",
        "file_path": None,
    },
    {
        "label": "secret, sans paquet",
        "repo_id": 12,
        "container_id": None,
        "finding_type": "secret",
        "identifier": "aws-access-token",
        "purl": None,
        "package_name": None,
        "file_path": "config/settings.py",
    },
    {
        "label": "constat Semgrep, chemin accentué",
        "repo_id": 12,
        "container_id": None,
        "finding_type": "sast",
        "identifier": "zanshin-python-eval-exec",
        "purl": None,
        "package_name": None,
        "file_path": "app/données/traitement.py",
    },
    {
        # Le séparateur est une barre verticale, pas un octet NUL comme pour le
        # journal d'audit. Un chemin qui en contient une peut donc, en principe,
        # imiter une frontière de champ. C'est une faiblesse du calcul existant,
        # reproduite telle quelle : la corriger changerait toutes les empreintes
        # déjà en base, donc résoudrait tout le backlog et détruirait les triages.
        "label": "chemin contenant le séparateur",
        "repo_id": 12,
        "container_id": None,
        "finding_type": "sast",
        "identifier": "regle",
        "purl": None,
        "package_name": None,
        "file_path": "a|b",
    },
    {
        "label": "tous les champs optionnels absents",
        "repo_id": 1,
        "container_id": None,
        "finding_type": "",
        "identifier": None,
        "purl": None,
        "package_name": None,
        "file_path": None,
    },
]


def _build_fingerprint(
    *, repo_id, container_id, finding_type, identifier, purl, package_name, file_path
) -> str:
    """Copie fidèle de `zanshin.models.issue.build_fingerprint`.

    Recopiée pour la même raison que `_audit_entry_hash` : importer le modèle
    tirerait `zanshin.database`, qui construit son moteur à l'import et créerait un
    fichier SQLite au passage. Un script de génération de vecteurs n'a pas à toucher
    de base. `tests/test_parity_vectors.py` confronte les deux implémentations.
    """
    target = f"repo:{repo_id}" if repo_id is not None else f"container:{container_id}"
    parts = [
        target,
        finding_type or "",
        identifier or "",
        purl or package_name or "",
        file_path or "",
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def build_fingerprint_vectors() -> list[dict]:
    vectors = []
    for case in FINGERPRINT_CASES:
        arguments = {key: value for key, value in case.items() if key != "label"}
        vectors.append(
            {
                "label": case["label"],
                "input": {
                    "repoId": case["repo_id"],
                    "containerId": case["container_id"],
                    "findingType": case["finding_type"],
                    "identifier": case["identifier"],
                    "purl": case["purl"],
                    "packageName": case["package_name"],
                    "filePath": case["file_path"],
                },
                "expected": _build_fingerprint(**arguments),
            }
        )
    return vectors


def _gate_issue(**overrides):
    """Un objet portant les attributs que `evaluate` regarde, et rien d'autre.

    `evaluate` n'accède qu'à une dizaine d'attributs, jamais à la session : un simple
    porteur d'attributs suffit, et évite de construire une ligne `Issue` — donc
    d'ouvrir une base — pour tester des fonctions pures.
    """
    from types import SimpleNamespace

    fields = {
        "id": 1,
        "state": "open",
        "type": "vulnerability",
        "severity": "high",
        "identifier": "CVE-2024-1234",
        "package_name": "requests",
        "fix_versions": "2.32.0",
        "is_kev": False,
        "triage_status": "under_review",
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


# Les combinaisons où une erreur de portage change le verdict d'une compilation.
GATE_CASES = [
    ("backlog vide", [], {}),
    ("une high sous le seuil high par défaut", [{}], {}),
    ("une medium sous le seuil high", [{"severity": "medium"}], {}),
    ("une medium sous un seuil medium", [{"severity": "medium"}], {"fail_on_severity": "medium"}),
    (
        "unknown se classe sous low et ne déclenche rien",
        [{"severity": "unknown"}],
        {"fail_on_severity": "low"},
    ),
    ("une sévérité hors vocabulaire se classe en dernier", [{"severity": "catastrophique"}], {}),
    ("un problème résolu n'est pas évalué", [{"state": "resolved"}], {}),
    (
        "un KEV medium échoue quand même",
        [{"severity": "medium", "is_kev": True}],
        {},
    ),
    (
        "KEV désactivé : la sévérité seule décide",
        [{"severity": "medium", "is_kev": True}],
        {"fail_on_kev": False},
    ),
    (
        "un KEV ne produit qu'une violation, la règle KEV",
        [{"severity": "critical", "is_kev": True}],
        {},
    ),
    (
        "la qualité ne vote jamais, même en critique",
        [{"type": "quality", "severity": "critical"}],
        {},
    ),
    (
        "la qualité reste exclue même avec include_ai_review",
        [{"type": "quality", "severity": "critical"}],
        {"include_ai_review": True},
    ),
    ("la revue IA est exclue par défaut", [{"type": "ai_review", "severity": "critical"}], {}),
    (
        "la revue IA vote si on le demande",
        [{"type": "ai_review", "severity": "critical"}],
        {"include_ai_review": True},
    ),
    (
        "un problème trié not_affected est écarté",
        [{"triage_status": "not_affected", "severity": "critical"}],
        {},
    ),
    (
        "include_triaged le fait revenir",
        [{"triage_status": "not_affected", "severity": "critical"}],
        {"include_triaged": True},
    ),
    (
        "fixable_only écarte ce qui n'a pas de correctif",
        [{"severity": "critical", "fix_versions": None}],
        {"fixable_only": True},
    ),
    (
        "fixable_only laisse passer un KEV sans correctif — le cas qui demande un humain",
        [{"severity": "medium", "fix_versions": "", "is_kev": True}],
        {"fixable_only": True},
    ),
    (
        "sans règle de sévérité, seul KEV décide",
        [{"severity": "critical"}, {"id": 2, "severity": "critical", "is_kev": True}],
        {"fail_on_severity": None},
    ),
    (
        "comptage par sévérité sur un backlog mêlé",
        [
            {"id": 1, "severity": "critical"},
            {"id": 2, "severity": "high"},
            {"id": 3, "severity": "high"},
            {"id": 4, "severity": "low"},
            {"id": 5, "severity": None},
            {"id": 6, "type": "quality", "severity": "critical"},
            {"id": 7, "state": "resolved", "severity": "critical"},
        ],
        {},
    ),
]


HARDEN_CASES = [
    ("rien de demandé", {}, {}),
    # Attention au sens, c'est le piège de cette fonction : le seuil est une
    # sévérité *minimale* pour échouer. Descendre de « high » à « low » fait
    # échouer sur davantage de problèmes — c'est un durcissement. Monter à
    # « critical » en fait échouer moins — c'est un assouplissement, donc refusé.
    ("un seuil plus bas (low) fait échouer davantage : durcissement", {}, {"fail_on_severity": "low"}),
    ("un seuil plus haut (critical) fait échouer moins : refusé", {}, {"fail_on_severity": "critical"}),
    ("retirer la règle de sévérité est refusé", {}, {"fail_on_severity": None}),
    (
        "retirer une règle qui n'existe pas ne refuse rien",
        {"fail_on_severity": None},
        {"fail_on_severity": None},
    ),
    (
        "ajouter une règle là où il n'y en avait pas est un durcissement",
        {"fail_on_severity": None},
        {"fail_on_severity": "medium"},
    ),
    ("un seuil identique ne signale rien", {}, {"fail_on_severity": "high"}),
    ("désactiver KEV est refusé", {}, {"fail_on_kev": False}),
    ("activer KEV quand il l'est déjà ne signale rien", {}, {"fail_on_kev": True}),
    ("inclure les triés est un durcissement", {}, {"include_triaged": True}),
    ("exclure les triés quand ils l'étaient déjà ne signale rien", {}, {"include_triaged": False}),
    (
        "repasser fixable_only à faux est un durcissement",
        {"fixable_only": True},
        {"fixable_only": False},
    ),
    ("activer fixable_only est refusé", {}, {"fixable_only": True}),
    (
        "plusieurs refus à la fois",
        {},
        {"fail_on_severity": "low", "fail_on_kev": False, "fixable_only": True},
    ),
]


def build_gate_vectors() -> dict:
    """Verdicts et durcissements produits par le vrai code Python.

    Importe `zanshin.services.policy_gate` plutôt que d'en recopier la logique : ce
    sont quarante lignes de règles imbriquées, qui se recopient mal. L'import
    n'ouvre aucune connexion — SQLAlchemy ne crée le fichier qu'à la première
    requête — ce que vérifie `tests/test_parity_vectors.py`.
    """
    import sys

    sys.path.insert(0, str(REPO_ROOT))
    from zanshin.services.gate_policy_service import harden
    from zanshin.services.policy_gate import GatePolicy, evaluate

    def camel(name: str) -> str:
        head, *rest = name.split("_")
        return head + "".join(word.capitalize() for word in rest)

    verdicts = []
    for label, issue_overrides, policy_fields in GATE_CASES:
        issues = [_gate_issue(**{"id": index + 1, **overrides}) for index, overrides in enumerate(issue_overrides)]
        policy = GatePolicy(**policy_fields)
        verdict = evaluate(issues, policy)
        verdicts.append(
            {
                "label": label,
                "issues": [
                    {camel(key): value for key, value in vars(issue).items()} for issue in issues
                ],
                "policy": {camel(key): value for key, value in policy._asdict().items()},
                "expected": {
                    "passed": verdict.passed,
                    "evaluated": verdict.evaluated,
                    "countsBySeverity": verdict.counts_by_severity,
                    "violations": [
                        {
                            "rule": violation.rule,
                            "issueId": violation.issue_id,
                            "identifier": violation.identifier,
                            "severity": violation.severity,
                            "package": violation.package,
                            "fixVersions": violation.fix_versions,
                            "reason": violation.reason,
                        }
                        for violation in verdict.violations
                    ],
                },
            }
        )

    hardenings = []
    for label, base_fields, requested in HARDEN_CASES:
        base = GatePolicy(**base_fields)
        policy, ignored = harden(base, requested)
        hardenings.append(
            {
                "label": label,
                "base": {camel(key): value for key, value in base._asdict().items()},
                "requested": {camel(key): value for key, value in requested.items()},
                "expected": {
                    "policy": {camel(key): value for key, value in policy._asdict().items()},
                    "ignoredRelaxations": ignored,
                },
            }
        )

    return {"verdicts": verdicts, "hardenings": hardenings}


def _export_issue(**overrides):
    """Un problème complet, tel que les exports le lisent.

    Comme pour le gate : `build_sarif_document` et ses voisines ne touchent ni la
    session ni la base, un porteur d'attributs suffit.
    """
    from types import SimpleNamespace

    fields = {
        "id": 1,
        "fingerprint": "f" * 64,
        "type": "vulnerability",
        "identifier": "CVE-2024-1234",
        "severity": "high",
        "cvss_score": 7.5,
        "epss_score": 0.42,
        "is_kev": False,
        "package_name": "requests",
        "package_version": "2.31.0",
        "purl": "pkg:pypi/requests@2.31.0",
        "is_direct_dependency": True,
        "file_path": "requirements.txt",
        "line": 12,
        "fix_state": "fixed",
        "fix_versions": "2.32.0",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        "description": "Une description de la vulnérabilité.",
        "state": "open",
        "triage_status": "under_review",
        "triage_justification": None,
        "triage_comment": None,
        "triaged_by": None,
        "triaged_at": None,
        "triage_expires_at": None,
        "first_seen_at": datetime(2026, 1, 5, 9, 30, 0),
        "last_seen_at": datetime(2026, 8, 1, 14, 0, 0, 500000),
        "times_seen": 4,
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


# Les situations où une erreur de portage produit un document valide mais faux.
EXPORT_CASES = [
    ("backlog vide", []),
    ("une vulnérabilité ordinaire", [{}]),
    (
        "un problème résolu est exclu de SARIF, et déclaré fixed en VEX",
        [{"state": "resolved"}],
    ),
    (
        "un not_affected devient une suppression SARIF et porte sa justification",
        [
            {
                "triage_status": "not_affected",
                "triage_justification": "vulnerable_code_not_in_execute_path",
                "triage_comment": "Le module n'est pas chargé en production.",
                "triaged_by": "alice",
                "triaged_at": datetime(2026, 6, 1, 10, 0, 0),
                "triage_expires_at": datetime(2026, 12, 1, 10, 0, 0),
            }
        ],
    ),
    (
        "un affected reste visible et porte un action_statement",
        [{"triage_status": "affected", "triage_comment": "Correctif planifié en sprint 12."}],
    ),
    ("un fixed est supprimé dans SARIF", [{"triage_status": "fixed"}]),
    (
        "un constat de qualité est étiqueté quality, pas security",
        [{"type": "quality", "identifier": "zanshin-python-bare-except", "purl": None, "package_name": None, "package_version": None}],
    ),
    (
        "un secret, sans paquet ni purl",
        [{"type": "secret", "identifier": "aws-access-token", "purl": None, "package_name": None, "package_version": None, "severity": "high", "file_path": "config/settings.py", "line": 3}],
    ),
    (
        "un constat sans fichier retombe sur la racine du dépôt",
        [{"file_path": None, "line": None}],
    ),
    (
        "un KEV sans correctif, message complet",
        [{"is_kev": True, "fix_versions": None, "fix_state": "not-fixed", "severity": "critical"}],
    ),
    (
        "une dépendance transitive le dit dans le message",
        [{"is_direct_dependency": False}],
    ),
    (
        "l'absence d'information sur la dépendance ne s'invente pas",
        [{"is_direct_dependency": None}],
    ),
    (
        "deux problèmes partageant un identifiant ne produisent qu'une règle",
        [{"id": 1, "file_path": "a.txt"}, {"id": 2, "file_path": "b.txt"}],
    ),
    (
        "même identifiant, types différents : deux règles distinctes",
        [{"id": 1, "type": "secret"}, {"id": 2, "type": "iac"}],
    ),
    (
        "un problème sans identifiant",
        [{"identifier": None, "type": "eol"}],
    ),
    (
        "une sévérité hors vocabulaire retombe sur warning et n'a pas de security-severity",
        [{"severity": "catastrophique"}],
    ),
    (
        "un type non vulnérable est écarté de VEX",
        [{"type": "iac", "identifier": "CKV_AWS_1"}],
    ),
    (
        "une vulnérabilité sans identifiant est écartée de VEX",
        [{"identifier": None}],
    ),
    (
        # Le piège du CSV : virgules, guillemets et sauts de ligne. `csv.DictWriter`
        # met des guillemets et double ceux du contenu, et termine ses lignes en CRLF.
        "champs contenant virgule, guillemets et saut de ligne",
        [
            {
                "description": 'Contient une virgule, un "guillemet" et\nun saut de ligne.',
                "triage_status": "not_affected",
                "triage_justification": "component_not_present",
                "triage_comment": 'Commentaire, avec "citation"\net retour.',
                "triaged_by": "bob",
                "triaged_at": datetime(2026, 6, 1, 10, 0, 0),
            }
        ],
    ),
    (
        "scores absents et times_seen nul",
        [{"cvss_score": None, "epss_score": None, "times_seen": 0, "line": None, "severity": None}],
    ),
    (
        # `str(9.0)` vaut « 9.0 » en Python et « 9 » en JavaScript. Sur une colonne
        # de score CVSS, la moitié des valeurs sont entières.
        "scores entiers, rendus avec leur décimale",
        [{"cvss_score": 9.0, "epss_score": 1.0}],
    ),
    (
        "score à zéro, qui n'est pas une absence de score",
        [{"cvss_score": 0.0, "epss_score": 0.0}],
    ),
]


def build_export_vectors() -> dict:
    """Documents SARIF, OpenVEX et CSV produits par le vrai `zanshin.services.exports`.

    Importé, pas recopié : quatre cents lignes de mise en forme, dont les subtilités
    (suppressions plutôt qu'omissions, location obligatoire, `security-severity`
    numérique, CRLF du module `csv`) sont précisément ce qu'un portage rate.
    """
    import sys

    sys.path.insert(0, str(REPO_ROOT))
    from zanshin.services.exports import (
        build_issues_csv,
        build_openvex_document,
        build_sarif_document,
    )

    vectors = []
    for label, issue_overrides in EXPORT_CASES:
        issues = [_export_issue(**{"id": index + 1, **overrides}) for index, overrides in enumerate(issue_overrides)]
        vectors.append(
            {
                "label": label,
                "issues": [_serialize_issue(issue) for issue in issues],
                "sarif": build_sarif_document(
                    issues,
                    target_name="org/exemple",
                    tool_version="1.2.3",
                    information_uri="https://zanshin.interne",
                ),
                "openvex": build_openvex_document(
                    issues,
                    author="Zanshin <security@exemple.be>",
                    product_id="pkg:github/org/exemple",
                    document_id="https://zanshin.interne/vex/1",
                    timestamp="2026-08-10T08:00:00",
                    version=3,
                ),
                "csv": build_issues_csv(issues),
            }
        )
    return {
        "cases": vectors,
        # Sans `informationUri`, la clé doit être absente et non nulle.
        "sarifWithoutInformationUri": build_sarif_document([_export_issue()], target_name="org/exemple", tool_version="1.2.3"),
    }


def _serialize_issue(issue) -> dict:
    """Le problème sous la forme que lit le code TypeScript : camelCase, horodatages
    en texte (jamais un `Date`, qui perdrait la microseconde)."""

    def camel(name: str) -> str:
        head, *rest = name.split("_")
        return head + "".join(word.capitalize() for word in rest)

    serialized = {}
    for key, value in vars(issue).items():
        serialized[camel(key)] = value.isoformat() if isinstance(value, datetime) else value
    return serialized


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    written = []
    for name, payload in (
        ("audit-hash.json", build_audit_vectors()),
        ("python-timestamp.json", build_timestamp_vectors()),
        ("issue-fingerprint.json", build_fingerprint_vectors()),
        ("policy-gate.json", build_gate_vectors()),
        ("exports.json", build_export_vectors()),
    ):
        path = OUTPUT_DIR / name
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        count = len(payload) if isinstance(payload, list) else sum(len(group) for group in payload.values())
        written.append(f"{path.relative_to(REPO_ROOT)} ({count} vecteurs)")
    print("Écrit :\n  " + "\n  ".join(written))


if __name__ == "__main__":
    main()
