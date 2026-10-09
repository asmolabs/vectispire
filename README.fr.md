# Vectispire

*[English version](README.md)*

Vectispire est une plateforme auto-hébergée qui suit la sécurité des logiciels que vous produisez.
Elle analyse des dépôts Git et des images de conteneurs — les dépendances par un SBOM, les
vulnérabilités connues, les secrets en clair, les licences, les environnements arrivés en fin de
vie, l'infrastructure-as-code et, en option, le code source lui-même — et conserve chaque constat
comme une issue dotée d'un historique, d'une décision de triage et d'un verdict qu'un pipeline CI
peut demander. Chaque scanner tourne dans un conteneur sans réseau, sur vos machines.

Un plan de contrôle Spring Boot sur JDK 25, une interface Angular, MySQL ou PostgreSQL, sous
[licence Apache 2.0](LICENSE). **Le projet n'a pas atteint la 1.0** : `0.10.x` est la ligne suivie
([SECURITY.md](SECURITY.md)), et le guide utilisateur est publié sur
<https://asmolabs.github.io/vectispire/>.

## À quoi il sert

L'essentiel de ce que Vectispire trouve, d'autres outils le trouvent aussi — il lance Syft, Grype,
Gitleaks, Checkov et Semgrep plutôt que de les réécrire. Ce qu'il ajoute, c'est ce qui se passe
**après** qu'un scanner a parlé :

- **Une décision de triage qui dure.** Un constat devient une issue identifiée par une empreinte qui
  ignore la version du paquet : une dépendance qui reste vulnérable sur trois versions correctives
  garde un seul historique et une seule décision. Les décisions suivent le vocabulaire VEX, peuvent
  porter une date de revue, et s'exportent en OpenVEX, CSAF 2.0, CycloneDX et en suppressions SARIF
  — on trie une fois, pas une fois par outil.
- **Un historique écrit pour quelqu'un qui n'était pas là.** Par dépôt : chaque analyse, la version
  lue, ce qu'elle a observé, et chaque décision prise — par qui, de quel statut vers quel statut,
  avec quelle justification. Exportable en PDF et CSV, pour un auditeur ou une revue d'incident.
- **Une barrière qui dit pourquoi.** Un pipeline demande « ce build doit-il échouer ? » et reçoit le
  verdict, la politique stockée et versionnée qui l'a produit, et trois codes de sortie — parce que
  « le plan de contrôle était injoignable » ne doit pas se lire « votre code est propre ».
- **Les preuves qu'un audit ISO/IEC 27001 demande.** Une déclaration d'applicabilité qui confronte
  le déclaré au mesuré, un périmètre certifié comparé à ce qui est réellement surveillé, un
  registre des risques acceptés qui montre les échus et les jamais revus, les checklists de
  sécurité de l'organisation validées par projet, les délais de remédiation par leur queue, et
  l'état du parc à une heure donnée — chacun décrit [plus bas](#fonctionnalités).
- **Un scanner qui a échoué n'est pas un résultat propre.** Une analyse qui n'a pas tourné rend
  *absent*, jamais une liste vide : elle ne peut pas fermer un backlog qu'elle n'a pas regardé
  ([décision 0007](docs/architecture/fr/decisions/0007-none-is-not-an-empty-list.md)).
- **Rien de votre code ne quitte la machine.** Les scanners tournent sans réseau, sur un montage en
  lecture seule et sans aucune capacité ; les données EPSS et CISA KEV sont téléchargées en entier,
  si bien qu'aucun tiers n'apprend quelle CVE porte un dépôt. Des agents distants analysent depuis
  d'autres segments réseau et n'ont, par construction, aucun accès à la base.

Le raisonnement derrière chacun de ces points — et les alternatives écartées — se trouve dans le
[registre des décisions](docs/architecture/fr/decisions/README.md), avec le
[modèle de menaces](docs/architecture/security/fr/STRIDE_THREAT_MODEL.fr.md) et les audits qui
consignent les erreurs de ce projet.

*Le nom réunit* vectis, *le levier ou le verrou en latin — la barrière — et* spire, *un point
élevé d'où voir tout le parc.*

## Fonctionnalités

- **Dépendances et vulnérabilités** : SBOM (Syft) et correspondance des vulnérabilités (Grype),
  enrichies du score EPSS et du statut « activement exploitée » du catalogue CISA KEV. Chaque issue
  dit si le paquet est une dépendance **directe** ou transitive : la première se corrige cet
  après-midi, la seconde attend une version amont.
- **Secrets** (Gitleaks) : Vectispire garde le fichier, la ligne et la règle, **jamais la valeur** —
  un secret détecté se révoque, il ne s'archive pas dans une base, un export et un ticket.
- **Licences, fin de vie, IaC** : liste de licences refusées évaluée sur le SBOM ; plateformes et
  environnements dont le support de sécurité est terminé (endoflife.date) ; erreurs de
  configuration Terraform et Kubernetes (Checkov).
- **Analyse du code source** (Semgrep, désactivée par défaut) : constats de *sécurité*, soumis à la
  barrière, et de *qualité*, visibles mais incapables de faire échouer un build. Vectispire ne
  livre qu'une règle — les jeux publics ne sont pas redistribuables — et la couverture vient d'un
  jeu que vous installez ([décision 0006](docs/architecture/fr/decisions/0006-semgrep-rules-written-here.md)).
- **Triage** individuel ou en masse, avec justification, date de revue et historique de chaque
  transition ; une issue revient *en revue* à sa date.
- **OWASP Top 10:2021 semaine par semaine** (`/owasp`) : le backlog par catégorie de l'OWASP Top 10:2021 (la seule édition que couvre la correspondance), en carte
  de chaleur et en courbes. Les semaines antérieures à l'enregistrement sont reconstituées et
  hachurées, pour qu'un changement de définition ne se lise pas comme un progrès.
- **Barrière CI** : script [`ci/vectispire-gate.sh`](ci/vectispire-gate.sh), action GitHub et
  modèle GitLab ; politiques globales ou par cible, versionnées, qu'une requête peut durcir mais
  jamais assouplir.
- **Exports** : SARIF 2.1.0 (GitHub, GitLab, Azure DevOps), OpenVEX, CSAF 2.0, CycloneDX VEX, CSV,
  SBOM, et deux documents PDF écrits pour une personne : la posture d'une cible et son historique
  de détection et de triage.
- **Éléments de conformité** : ce que les analyses observent, et ce que la plateforme a elle-même
  activé (chiffrement, copie du journal d'audit, double validation des exemptions, SSO), rapporté
  aux contrôles de **NIS 2**, **DORA**, **ISO/IEC 27001:2022**, **PCI-DSS v4.0**, du **Cyber
  Resilience Act** et de **SOC 2**, avec un dossier de preuves signé. Cela prépare une évaluation,
  ce n'en est pas une — un parc que personne n'a analysé récemment est plafonné, pas noté sur ses
  zéro constats.
- **Piloter un SMSI ISO/IEC 27001.** Les écrans qu'un auditeur demande, chacun construit autour de
  la question à laquelle un tableau de bord ne répond pas :
  - **Déclaration d'applicabilité** (`/soa`) : ce qui est déclaré pour chaque mesure, confronté à ce
    que le parc mesure, trié par **divergence** plutôt que par numéro — une mesure déclarée en place
    et mesurée non conforme est exactement ce qu'un auditeur relève. La clause 6.1.3 d exige que
    chaque mesure soit traitée : une mesure non déclarée apparaît comme un écart, et celle dont la
    preuve vit dans un autre document est marquée *non mesurée ici* plutôt que comme un constat
    ([guide](docs-site/guide/statement-of-applicability.fr.md)).
  - **Périmètre certifié** (`/certified-scope`) : les actifs que nomme le document de périmètre,
    face à ceux que l'instance connaît, et combien portent une preuve à jour. Rien n'est dans le
    périmètre par défaut : un périmètre que personne n'a tracé se lit « non déclaré », pas comme un
    pourcentage d'un dénominateur inconnu ([guide](docs-site/guide/certified-scope.fr.md)).
  - **Exceptions** (`/exceptions`) : ce qui a été accepté plutôt que corrigé, avec les deux nombres
    qui comptent — les acceptations dont la durée est échue, et celles que personne n'a revues
    depuis qu'elles ont été accordées. Accorder et revoir sont réservés au responsable sécurité, et
    l'exemption demandée par un développeur peut exiger une seconde personne
    ([guide](docs-site/guide/exceptions.fr.md)).
  - **Checklists de sécurité** : la checklist de l'organisation, importée de son classeur comme
    modèle, remplie par projet avec des preuves datées qui expirent, puis validée par un
    approbateur ; une révision validée n'est plus jamais modifiée
    ([décision 0032](docs/architecture/fr/decisions/0032-security-checklists.md),
    [guide](docs-site/guide/security-checklists.fr.md)).
  - **Délais de remédiation** (`/remediation-delays`) : la part corrigée dans son délai, le 90ᵉ
    centile et le plus ancien élément encore ouvert — la queue de la distribution, pas une moyenne
    tirée vers le bas par les corrections faciles.
  - **Historique de conformité** (`/compliance-history`) : chaque référentiel mois par mois, chaque
    mois portant sa cause plausible, et une série dont le parc a changé annoncée *non comparable*
    plutôt que tracée comme une régression. Pas de score global : un agrégat s'améliore en ajoutant
    un référentiel facile.
  - **Attestation** (`/attestation`) : l'état du parc à une heure donnée, chaîne d'audit vérifiée
    d'abord — la question est « où en étiez-vous le jour où j'ai regardé », et aucun autre écran ne
    porte d'heure ([guide](docs-site/guide/attestation.fr.md)).
- **Comparaison de SBOM** entre deux analyses, **estimation de l'effort de remédiation** et les
  montées de version qui ferment le plus d'issues à la fois.
- **Tickets** GitLab et Jira, **notifications** webhook signé, Teams et e-mail, **rapport
  hebdomadaire** de posture, **réanalyse périodique**, **SSO** OpenID Connect optionnel.

Le détail de chaque fonctionnalité, et ce qu'elle refuse de faire, est dans le
[README anglais](README.md) et dans la [documentation](#documentation).

## Démarrage rapide

Prérequis : JDK 25, Node 24 (épinglé par `.nvmrc` — Angular refuse Node 25), et Docker, pour les
scanners et, en développement, pour la base. `docker compose up` lance toute la pile à la place ;
le [guide d'installation](https://asmolabs.github.io/vectispire/) le décrit.

```bash
npm ci
cd vectispire-java && ./gradlew :vectispire-core:bootRun   # API sur http://localhost:3180
npm --workspace @vectispire/frontend start            # interface sur http://localhost:4280
```

Le schéma appartient aux migrations Flyway, appliquées au démarrage ; `ddl-auto` reste `validate`.

### Pages principales

| Route | Description |
|---|---|
| `/dashboard` | Vue d'ensemble |
| `/security` | Verdict de la barrière pour chaque cible, et la politique qui l'a produit |
| `/issues` | Backlog des issues à travers les analyses, avec le triage (VEX) |
| `/owasp` | Le backlog par catégorie de l'OWASP Top 10:2021, semaine par semaine |
| `/quality` | Constats de qualité du code, par règle, fichier et dépôt |
| `/repositories` | Dépôts Git suivis, historique des analyses, détail des constats |
| `/containers` | Images de conteneurs suivies |
| `/inventory` | Inventaire des dépendances et comparaison de SBOM |
| `/compliance` | Contrôles par référentiel et exports pour l'audit |
| `/history` | Par dépôt : chaque analyse, sa version, ses issues et chaque décision — export PDF et CSV |
| `/ssh-keys` | Clés SSH chiffrées pour cloner les dépôts privés |
| `/api-keys` | Clés d'API (hachage Argon2id, secret montré une fois) |
| `/agents` | Agents d'analyse (intégré et distants), la file et les baux (administration) |
| `/users`, `/teams` | Comptes, rôles et visibilité par équipe (administration) |
| `/audit-log` | Journal d'audit des actions sensibles (administration) |
| `/settings` | Paramètres d'exécution, liste de licences, intégrations |

## Documentation

- [Guide utilisateur](https://asmolabs.github.io/vectispire/) — installation, administration,
  intégration CI
- [Premiers pas](docs/fr/GETTING_STARTED.fr.md) et
  [documentation technique](docs/fr/TECHNICAL_DOCUMENTATION.fr.md)
- [Référence de l'API REST](docs/fr/api/rest_api_reference.md)
- [Intégration CI/CD](docs/fr/CI_CD_INTEGRATION.fr.md) et
  [conformité réglementaire](docs/fr/COMPLIANCE_AND_REGULATORY.fr.md)
- [Rotation d'`ENCRYPTION_KEY`](docs/fr/KEY_ROTATION.fr.md) et
  [sauvegarde et restauration](docs/fr/BACKUP_AND_RESTORE.fr.md) — vérifiée chaque nuit, pas
  seulement écrite
- [Exposition d'identifiants d'août 2026](docs/analysis/fr/2026-08-06_incident_exposition_identifiants.fr.md) — un compte
  rendu, pas une procédure
- [Dossier d'architecture](docs/architecture/fr/) et
  [registre des décisions](docs/architecture/fr/decisions/README.md)

## Contribuer et sécurité

Les contributions sont bienvenues — [CONTRIBUTING.md](CONTRIBUTING.md) dit où va une pull request
et ce qu'elle doit apporter, et toute personne qui participe suit le
[Code de conduite](CODE_OF_CONDUCT.md). **Une vulnérabilité se signale en privé**, comme le décrit
[SECURITY.md](SECURITY.md), jamais dans un ticket public.

## Licence

Vectispire est distribué sous [licence Apache 2.0](LICENSE), octroi de brevets compris ; les
contributions sont placées sous les mêmes conditions, sans accord de contribution.
[`NOTICE`](NOTICE) liste les composants tiers que le jar et l'image embarquent. La licence couvre le
code, pas le nom : Apache-2.0 n'accorde aucun droit sur la marque, et un fork peut tout reprendre
sauf le nom Vectispire.
