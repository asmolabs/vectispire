# 0003 — Les agents parlent en long-polling HTTP, jamais à la base

**Date :** 2026-08-06 · **Statut :** acceptée

## Contexte

Déporter l'exécution des scans sur des machines distantes — un autre réseau, une autre
architecture, une machine autorisée à joindre un dépôt privé que le plan de contrôle ne
peut pas atteindre.

La question posée était le transport. La vraie question était l'accès aux secrets.

## Décision

`GET /api/v1/agents/jobs?wait=30` renvoie une tâche ou 204. L'agent réclame, exécute,
envoie un battement de cœur, remonte le résultat. Il **ne parle qu'à l'API**.

Quatre raisons, par ordre d'importance.

**L'agent n'a pas besoin d'accès à la base.** Un agent avec une connexion PostgreSQL
aurait aussi besoin des identifiants de la base *et* de `ENCRYPTION_KEY` — donc de quoi
déchiffrer **toutes** les clés SSH de toutes les cibles, pas seulement celles qu'il
scanne. En HTTP il ne présente qu'une clé à portée `agent`, et il réutilise
l'authentification, les portées, le quota et l'audit qui existent déjà.

**Le contrôle de flux se fait tout seul.** L'agent demande du travail quand il a de la
capacité. Un broker qui pousse ne sait pas ce que l'agent est en train de faire.

**La latence n'est pas un enjeu.** Un scan dure une à deux minutes ; un long-poll de trente
secondes coûte quelques pourcents.

**Conséquence utile :** comme seul le plan de contrôle touche la base, **les agents
fonctionnent même sur SQLite**. La forme de déploiement la plus simple gagne la
fonctionnalité la plus avancée, ce qui n'était pas prévu.

## Ce qu'on a écarté

**L'agent détient `ENCRYPTION_KEY` et lit la base.** Le moins de travail, et la
conséquence est dans le tableau ci-dessus : tout agent peut déchiffrer toutes les clés
SSH. Un agent est par nature la pièce la plus exposée — il tourne ailleurs, souvent sur
une machine dont on maîtrise moins la posture. Revenir en arrière après coup signifierait
faire tourner tous les secrets.

**Un SDK de plugins pour les agents.** Le point d'extension existe déjà et il est au bon
niveau : [`ScannerEngine`](0001-couche-de-scan-pluggable.md). Un agent est un *transport*
pour cette interface, pas une abstraction supplémentaire.

## Conséquences

`ScanProcessor` a dû être coupé en deux : `ScanRunner`, qui fait tourner les analyseurs et
ne connaît pas la base, et `ScanIngestor`, qui lit les artefacts et écrit. La coupure n'est
pas un rangement, c'est la formalisation du contrat de l'agent.

Un test d'imports garantit que le module agent ne peut pas importer la couche base. Sans
lui, la garantie serait une convention.

**Une remontée rejouée fausserait l'historique.** L'empreinte rend le rapprochement
idempotent, mais `sync_from_scan` incrémente `times_seen` à chaque appel — un rapport
rejoué gonflerait les compteurs sans créer de doublon visible. D'où une inbox de
déduplication (`processed_message`), avec l'identifiant inséré **dans la transaction qui
applique l'effet**.

**Un agent compromis peut fausser un verdict** en remontant des résultats mensongers. Les
remontées sont auditées comme un triage l'est ; elles ne sont pas prouvées. C'est la limite
ouverte de cette décision.
