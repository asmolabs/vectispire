# 02 — Modèle de données

## La distinction fondamentale : Finding vs Issue

C'est le concept essentiel à comprendre avant de manipuler ce schéma :

- Un **`Finding`** (Constat) est ce qu'un analyseur a renvoyé au cours d'**un seul scan**. Il est
  immuable et jetable. Exécuter un nouveau scan produit un nouveau constat.
- Une **`Issue`** (Problème) est le même problème **suivi d'un scan à l'autre**. Elle possède une
  date de première détection, un compteur d'occurrences, un état (`OPEN`/`RESOLVED`), une décision
  de triage VEX et son auteur.

```mermaid
erDiagram
    REPOSITORY ||--o{ SCAN : "est analysé par"
    CONTAINER  ||--o{ SCAN : "est analysé par"
    SCAN       ||--o{ FINDING : "produit"
    SCAN       ||--o{ ISSUE : "ouvre (first_seen)"
    ISSUE      }o--|| REPOSITORY : "concerne"
    ISSUE      }o--|| CONTAINER : "concerne"
    REPOSITORY ||--o| SSH_KEY : "clone avec"
    REPOSITORY ||--o| GATE_POLICY : "évalué par"
    CONTAINER  ||--o| GATE_POLICY : "évalué par"
    SCAN       }o--o| AGENT : "pris en charge par"
    SCAN       ||--o{ AI_REVIEW_RESULT : "transporte"
```

**Le diagramme est un sous-ensemble délibéré : onze tables sur trente-trois.** Il montre le chemin
d'une analyse, parce que c'est la partie dont il faut comprendre la forme avant de toucher au
schéma. Le reste — la billetterie, l'inventaire d'API, le renseignement sur les menaces, la
configuration SIEM, les sessions, les paramètres, le journal d'audit — s'y raccroche sans le
modifier. C'est `SchemaParityIntegrationTest` qui tient le compte honnête, et il a un jour affirmé
vingt-six contre un arbre de trente-trois : un nombre exact dans un document est un nombre que
personne ne met à jour.

## L'empreinte (Fingerprint)

L'identité d'une issue entre plusieurs scans est calculée par `IssueFingerprint` :

```
sha256( target, type, identifier, purl-or-package-name, file-path )
```

## Cycle de vie d'une Issue

```mermaid
stateDiagram-v2
    [*] --> open : première détection
    open --> open : détecté à nouveau (times_seen++)
    open --> resolved : absent d'un scan ayant vérifié ce type
    resolved --> open : réapparaît
    open --> under_review : qualification (triage)
    under_review --> not_affected : avec justification VEX
    under_review --> affected
    not_affected --> under_review : expiration de la révision
```

## Les migrations

Gérées par Flyway dans `vectispire-java/vectispire-core/src/main/resources/db/migration/{vendor}/`
(`postgresql`, `mysql`, `sqlite`) avec des scripts SQL natifs par dialecte assurant une fidélité
parfaite sur chaque moteur de base de données.
