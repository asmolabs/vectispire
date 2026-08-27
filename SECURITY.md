# Security Policy

Vectispire is a security product. A vulnerability in it is a vulnerability in whatever it was
bought to watch, so this page says how to report one and what happens next — including the parts
that are not flattering.

*Une version française suit.*

---

## Reporting a vulnerability

**Email `laurent.boucher@civadis.be` with `[vectispire-security]` in the subject.**

Do not open a GitHub issue. The tracker is public to everyone with access to the project, and a
report there is a disclosure before anyone has had a chance to fix it.

Useful in a report, in rough order of usefulness:

- what an attacker gets, in one sentence — that is what decides the priority;
- the version or commit you looked at;
- the smallest sequence that reproduces it;
- whether you have already told anybody else.

You do not need a proof of concept. A precise description of a flawed control is worth more than
an exploit for one that is not.

## What to expect

| | |
|---|---|
| Acknowledgement | within **3 working days** |
| First assessment — severity, and whether it is a defect | within **10 working days** |
| Fix on `develop` for something exploitable | as fast as the fix allows, and you will be told what "as fast" turned out to mean |
| Credit | your name, or none, whichever you prefer |

**These are honest numbers for a project of this size, not a support contract.** Vectispire is
maintained by a small team. If a deadline slips you will be told it slipped, rather than told
nothing — a report that goes quiet is the failure this policy exists to prevent.

## Supported versions

| Version | Supported |
|---|---|
| `0.9.x` | ✅ the current line |
| earlier | ❌ |

The project has not reached 1.0. There is no long-term support line yet, and pretending otherwise
would be the first thing wrong on this page.

## Scope

**In scope** — anything in this repository, and in particular:

- authorization: any way to see a repository, container, finding or secret that was not granted
  to the account, credential or team asking. This is the control the product exists to enforce
  and the one it has failed at before ([the audits say how
  often](docs/analysis/README.md));
- the scanner sandbox: any escape from an analysis container to the host, or any way to make a
  scanned repository's own configuration change how it is scanned;
- the remote agent: anything that lets an agent read the database, obtain `ENCRYPTION_KEY`, or
  claim work belonging to another deployment;
- cryptography: anything that weakens secrets at rest, the sealed envelope to an agent, the
  audit chain, or password verification;
- the ticketing webhook, which is the one entry point reachable without an account.

**Out of scope**, and stated so you do not spend an evening on it:

- missing security headers with no demonstrated impact;
- rate limits reached by a tool you pointed at a demo instance;
- findings from an automated scanner pasted without a reading of what they mean here;
- vulnerabilities in a dependency that Vectispire does not reach — tell us anyway, but as a
  dependency report rather than as a vulnerability in the product;
- **the host-SSH fallback being on by default.** It is documented, deliberate, and switched off
  with `VECTISPIRE_HOST_SSH=false`; see the P2 row of the [threat
  model](docs/architecture/security/en/STRIDE_THREAT_MODEL.en.md).

## Safe harbour

Test against your own installation. If you do that, stay within what a report needs, and do not
access data belonging to other people, we will not pursue you and we will not ask anybody else to.

That undertaking covers what we control. It cannot cover a third party whose deployment you
tested without their permission.

## What we do on our side

Named because a policy that only asks is not a policy:

- the pipeline runs the product's own scanners against the product — Gitleaks over the full
  history, Grype over the jar that ships, Checkov over the Dockerfiles and the pipeline itself;
- releases are signed with Sigstore keyless, and the signature is verified **before** publication
  with the command a consumer would run;
- the architecture decisions, the threat model and the audit reports are in the repository,
  including the ones that record where this project got it wrong.

---
---

# Politique de sécurité

Vectispire est un produit de sécurité. Une vulnérabilité chez lui est une vulnérabilité chez ce
qu'il a été acheté pour surveiller, donc cette page dit comment en signaler une et ce qui se
passe ensuite — y compris ce qui n'est pas flatteur.

## Signaler une vulnérabilité

**Écrire à `laurent.boucher@civadis.be` avec `[vectispire-security]` en objet.**

Pas de ticket GitHub : le suivi est visible de tous ceux qui ont accès au projet, et un rapport
là-bas est une divulgation avant que quiconque ait pu corriger.

Utile dans un rapport, par ordre d'utilité :

- ce qu'un attaquant obtient, en une phrase — c'est ce qui décide de la priorité ;
- la version ou le commit examiné ;
- la plus petite séquence qui reproduit ;
- si vous en avez déjà parlé à quelqu'un d'autre.

Une preuve de concept n'est pas nécessaire. La description précise d'un contrôle défaillant vaut
mieux qu'un exploit pour un contrôle qui ne l'est pas.

## Ce à quoi vous attendre

| | |
|---|---|
| Accusé de réception | sous **3 jours ouvrés** |
| Première évaluation — gravité, et s'il s'agit d'un défaut | sous **10 jours ouvrés** |
| Correctif sur `develop` pour quelque chose d'exploitable | aussi vite que le correctif le permet, et on vous dira ce que « aussi vite » aura voulu dire |
| Attribution | votre nom, ou aucun, à votre choix |

**Ce sont des délais honnêtes pour un projet de cette taille, pas un contrat de support.** Si un
délai glisse, on vous le dira — un rapport qui reste sans réponse est précisément l'échec que
cette politique existe pour empêcher.

## Versions suivies

| Version | Suivie |
|---|---|
| `0.9.x` | ✅ la ligne courante |
| antérieures | ❌ |

Le projet n'a pas atteint la 1.0. Il n'existe pas encore de ligne de support long terme, et
prétendre le contraire serait la première chose fausse sur cette page.

## Périmètre

**Dans le périmètre** — tout ce dépôt, et en particulier :

- l'autorisation : toute façon de voir un dépôt, un conteneur, un constat ou un secret qui n'a
  pas été accordé au compte, au jeton ou à l'équipe qui demande. C'est le contrôle que le produit
  existe pour appliquer, et celui auquel il a déjà échoué
  ([les audits disent combien de fois](docs/analysis/README.md)) ;
- le bac à sable des scanners : toute évasion d'un conteneur d'analyse vers l'hôte, ou toute
  façon de faire changer l'analyse par la configuration du dépôt analysé ;
- l'agent distant : tout ce qui lui permettrait de lire la base, d'obtenir `ENCRYPTION_KEY`, ou
  de réclamer du travail appartenant à un autre déploiement ;
- la cryptographie : tout ce qui affaiblit les secrets au repos, l'enveloppe scellée vers un
  agent, la chaîne d'audit ou la vérification des mots de passe ;
- le webhook de ticketing, seul point d'entrée joignable sans compte.

**Hors périmètre**, et dit pour que vous n'y passiez pas une soirée :

- en-têtes de sécurité manquants sans impact démontré ;
- limites de débit atteintes avec un outil pointé sur une instance de démonstration ;
- constats d'un scanner automatique recopiés sans lecture de ce qu'ils signifient ici ;
- vulnérabilités d'une dépendance que Vectispire n'atteint pas — signalez-les quand même, mais
  comme rapport de dépendance et non comme vulnérabilité du produit ;
- **le repli SSH hôte actif par défaut.** Il est documenté, délibéré, et se désactive avec
  `VECTISPIRE_HOST_SSH=false` ; voir la ligne P2 du
  [modèle de menaces](docs/architecture/security/fr/STRIDE_THREAT_MODEL.fr.md).

## Sphère de sécurité

Testez sur votre propre installation. Si vous vous en tenez à ce qu'un rapport exige et n'accédez
pas aux données d'autrui, nous n'engagerons aucune poursuite et n'en demanderons à personne.

Cet engagement couvre ce que nous maîtrisons. Il ne peut pas couvrir un tiers dont vous auriez
testé le déploiement sans son accord.

## Ce que nous faisons de notre côté

Nommé, parce qu'une politique qui se contente de demander n'en est pas une :

- le pipeline lance les scanners du produit contre le produit — Gitleaks sur tout l'historique,
  Grype sur le jar livré, Checkov sur les Dockerfiles et sur le pipeline lui-même ;
- les publications sont signées sans clé avec Sigstore, et la signature est vérifiée **avant**
  publication avec la commande qu'un consommateur lancerait ;
- les décisions d'architecture, le modèle de menaces et les rapports d'audit sont dans le dépôt,
  y compris ceux qui consignent les erreurs de ce projet.
