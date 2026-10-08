# Contributing to Vectispire

Vectispire watches other people's software supply chain, so a defect in it is a defect in what it
was trusted to see. This page says what a contribution has to carry to be merged — and why each
rule exists, since most of them were written after the mistake they prevent.

*Une version française suit.*

---

## Before you start

- **A vulnerability is not an issue.** Report it privately as [SECURITY.md](SECURITY.md) describes;
  a public issue is a disclosure before anyone could fix it.
- **Open an issue before a large change.** A new scanner, a new module, a schema change or a new
  route deserves a few lines of discussion first: the [decision register](docs/architecture/en/decisions/)
  may already record why it was rejected, and a pull request that reverses a decision has to
  argue with that decision, not ignore it.
- **Read [`AGENTS.md`](AGENTS.md) and [`vectispire-java/README.md`](vectispire-java/README.md).**
  They are written for anyone changing the code, human or not, and they list the traps that have
  already cost this project data.

Small fixes — a typo, a broken link, a test that pins an existing behaviour — need none of this.
Send them.

## Building it

| | |
|---|---|
| JDK | 25 |
| Node | 24, as `.nvmrc` pins it — Angular refuses Node 25 |
| Docker | required: the unit and HTTP suites run on MySQL in a container, and every scanner runs in one |

```bash
cd vectispire-java && ./gradlew build                # compile, unit, architecture and HTTP suites
cd vectispire-java && ./gradlew integrationTestAll   # PostgreSQL and MySQL — when the change touches persistence

npm ci && npm run lint && npm run build && npm test  # the Angular interface, from the repository root
```

A suite that cannot reach its database **fails**; it does not skip. That is deliberate — a suite
that skips itself reports green without having checked anything — so a red build without Docker
is not a flake.

## What a pull request carries

**Target `develop`.** `main` only moves by fast-forward to a commit whose pipeline is green, and
its history is linear: a pull request is rebased, not merged.

**One logical change per commit**, in the repository's style:

```
fix(area): what is now true, in one line

What was wrong, what changed, and how it was verified — the command that
was run and what it said.
```

`feat`, `fix`, `docs`, `test`, `refactor`, `chore` — `git log` shows the register.

**Tests that fail without your change.** Before sending a test, remove the guard it pins or flip
the condition, and check that the test goes red. A test that stays green without the code it is
about pins nothing, and this project has shipped several.

**Documentation in both languages.** A change of behaviour updates `docs-site/` and `docs/` in
English **and** French in the same pull request. If you do not write one of the two, say so in the
pull request and somebody will — but do not leave it silently out of step.

```bash
python3 scripts/check-doc-links.py && python3 scripts/check-doc-facts.py
```

**Comments that say why.** A comment restating the line below it is noise; one naming the defect a
guard prevents, or the alternative that failed, is what stops the next person from removing it.

## Rules the build enforces

These fail the pipeline, so knowing them saves a round trip:

- **Layering and module boundaries** — `ArchitectureTest` and `ModularityTest` (Spring Modulith).
  A service writing SQL, a controller touching JPA, or a module reaching into another's internals
  fails the build. A new entry in a module's `allowedDependencies` is a review decision; write its
  reason beside it.
- **Authorization coverage** — `AuthorizationCoverageTest`. A route that names a target resolves a
  `Visibility` and refuses with **404, never 403**: a refusal must look like an absence. Being
  signed in is not the same as being allowed to see *this* repository.
- **Migrations** — the schema belongs to Flyway, `ddl-auto` stays `validate`, and `V1`–`V39` are
  never edited. A migration whose structure differs between engines is written once per engine;
  `MigrationLayoutTest` refuses anything in between.
- **The API contract** — `ClientContractSpecTest`. When a route's shape changes, regenerate the
  contract and the client types, and commit both:

  ```bash
  cd vectispire-java && ./gradlew :vectispire-core:test --tests '*ClientContractSpecTest*' -Dvectispire.openapi.write=true
  cd .. && npm run generate:api --workspace @vectispire/frontend
  ```

- **Dependency verification** — every artifact is checked against
  `vectispire-java/gradle/verification-metadata.xml`. Adding or bumping a dependency means running
  `./gradle/update-verification-metadata.sh` and committing the diff, which is reviewed line by
  line: it is the one place where trust is extended to somebody else's code.
- **Secrets** — Gitleaks scans the full history. A test fixture shaped like a secret carries a
  trailing `// gitleaks:allow` and a comment saying the value is invented.

## Two things that look harmless and are not

- **An issue's fingerprint is a data contract.** Changing a rule id, a finding type or the way a
  path is normalized resolves every existing issue and recreates it, losing all triage on every
  installation — silently. Such a change needs a migration of the fingerprints, and a sentence in
  the pull request saying so.
- **A scanner that fails returns absent, never empty.** An empty list means "ran and found
  nothing", which closes the backlog
  ([decision 0007](docs/architecture/en/decisions/0007-none-is-not-an-empty-list.md)).

## The repository is public

No customer, employer or real project names in fixtures, comments or examples — use
`org.example` and invented names. A commit fixing a vulnerability says what is fixed, not how to
exploit the version before it.

## Licence

Vectispire is licensed under the [Apache License 2.0](LICENSE). By submitting a contribution you
agree that it is licensed under the same terms, as section 5 of the licence provides. There is no
separate contributor agreement to sign.

## Conduct

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

---
---

# Contribuer à Vectispire

Vectispire surveille la chaîne d'approvisionnement logicielle des autres : un défaut chez lui est un
défaut dans ce qu'on lui a confié de voir. Cette page dit ce qu'une contribution doit apporter pour
être intégrée — et pourquoi chaque règle existe, puisque la plupart ont été écrites après l'erreur
qu'elles empêchent.

## Avant de commencer

- **Une vulnérabilité n'est pas un ticket.** Signalez-la en privé comme le décrit
  [SECURITY.md](SECURITY.md) ; un ticket public est une divulgation avant que quiconque ait pu
  corriger.
- **Ouvrez un ticket avant un changement important.** Un nouveau scanner, un nouveau module, un
  changement de schéma ou une nouvelle route méritent quelques lignes de discussion d'abord : le
  [registre des décisions](docs/architecture/fr/decisions/) dit peut-être déjà pourquoi l'idée a été
  écartée, et une pull request qui revient sur une décision doit argumenter contre elle, pas
  l'ignorer.
- **Lisez [`AGENTS.md`](AGENTS.md) et [`vectispire-java/README.md`](vectispire-java/README.md).**
  Ils sont écrits pour quiconque modifie le code, humain ou non, et recensent les pièges qui ont
  déjà coûté des données à ce projet.

Les petites corrections — une coquille, un lien cassé, un test qui fige un comportement existant —
n'ont besoin de rien de tout cela. Envoyez-les.

## Construire

| | |
|---|---|
| JDK | 25 |
| Node | 24, comme l'épingle `.nvmrc` — Angular refuse Node 25 |
| Docker | nécessaire : les suites unitaires et HTTP tournent sur MySQL dans un conteneur, et chaque scanner tourne dans le sien |

```bash
cd vectispire-java && ./gradlew build                # compilation, suites unitaires, d'architecture et HTTP
cd vectispire-java && ./gradlew integrationTestAll   # PostgreSQL et MySQL — quand le changement touche la persistance

npm ci && npm run lint && npm run build && npm test  # l'interface Angular, depuis la racine du dépôt
```

Une suite qui ne joint pas sa base **échoue** ; elle ne se saute pas. C'est délibéré — une suite qui
se saute elle-même affiche vert sans rien avoir vérifié — donc un build rouge sans Docker n'est pas
un aléa.

## Ce qu'une pull request apporte

**Ciblez `develop`.** `main` n'avance que par avance rapide vers un commit dont le pipeline est
vert, et son historique est linéaire : une pull request est rebasée, pas fusionnée.

**Un changement logique par commit**, dans le style du dépôt :

```
fix(zone): ce qui est vrai désormais, en une ligne

Ce qui n'allait pas, ce qui a changé, et comment c'est vérifié — la
commande lancée et ce qu'elle a répondu.
```

`feat`, `fix`, `docs`, `test`, `refactor`, `chore` — `git log` montre le registre.

**Des tests qui échouent sans votre changement.** Avant d'envoyer un test, retirez la garde qu'il
fige ou inversez la condition, et vérifiez qu'il passe au rouge. Un test qui reste vert sans le code
qu'il concerne ne fige rien, et ce projet en a livré plusieurs.

**La documentation dans les deux langues.** Un changement de comportement met à jour `docs-site/`
et `docs/` en anglais **et** en français dans la même pull request. Si vous n'écrivez pas l'une des
deux, dites-le dans la pull request et quelqu'un s'en chargera — mais ne la laissez pas désynchronisée
en silence.

```bash
python3 scripts/check-doc-links.py && python3 scripts/check-doc-facts.py
```

**Des commentaires qui disent pourquoi.** Un commentaire qui répète la ligne suivante est du bruit ;
celui qui nomme le défaut qu'une garde empêche, ou l'alternative qui a échoué, est ce qui empêche la
personne suivante de la retirer.

## Les règles que le build applique

Elles font échouer le pipeline ; les connaître évite un aller-retour :

- **Couches et frontières de modules** — `ArchitectureTest` et `ModularityTest` (Spring Modulith).
  Un service qui écrit du SQL, un contrôleur qui touche JPA ou un module qui va chercher dans les
  internes d'un autre fait échouer le build. Une nouvelle entrée dans les `allowedDependencies` d'un
  module est une décision de revue ; écrivez sa raison à côté.
- **Couverture de l'autorisation** — `AuthorizationCoverageTest`. Une route qui nomme une cible
  résout une `Visibility` et refuse par **404, jamais 403** : un refus doit ressembler à une absence.
  Être connecté n'est pas être autorisé à voir *ce* dépôt.
- **Migrations** — le schéma appartient à Flyway, `ddl-auto` reste `validate`, et `V1`–`V39` ne sont
  jamais modifiées. Une migration dont la structure diffère selon le moteur est écrite une fois par
  moteur ; `MigrationLayoutTest` refuse tout entre-deux.
- **Le contrat d'API** — `ClientContractSpecTest`. Quand la forme d'une route change, régénérez le
  contrat et les types du client, et committez les deux (commandes dans la section anglaise
  ci-dessus).
- **Vérification des dépendances** — chaque artefact est vérifié contre
  `vectispire-java/gradle/verification-metadata.xml`. Ajouter ou monter une dépendance, c'est lancer
  `./gradle/update-verification-metadata.sh` et committer le diff, relu ligne à ligne : c'est le seul
  endroit où l'on étend sa confiance au code de quelqu'un d'autre.
- **Secrets** — Gitleaks parcourt tout l'historique. Une donnée de test qui a la forme d'un secret
  porte un `// gitleaks:allow` en fin de ligne et un commentaire disant que la valeur est inventée.

## Deux choses qui ont l'air anodines et ne le sont pas

- **L'empreinte d'une issue est un contrat de données.** Changer un identifiant de règle, un type
  de constat ou la normalisation d'un chemin résout toutes les issues existantes et les recrée, en
  perdant tout le triage sur chaque installation — en silence. Un tel changement demande une
  migration des empreintes, et une phrase dans la pull request qui le dit.
- **Un scanner qui échoue renvoie absent, jamais vide.** Une liste vide veut dire « a tourné et n'a
  rien trouvé », ce qui ferme le backlog
  ([décision 0007](docs/architecture/fr/decisions/0007-none-is-not-an-empty-list.md)).

## Le dépôt est public

Aucun nom de client, d'employeur ou de projet réel dans les données de test, les commentaires ou les
exemples — utilisez `org.example` et des noms inventés. Un commit qui corrige une vulnérabilité dit
ce qui est corrigé, pas comment exploiter la version d'avant.

## Licence

Vectispire est distribué sous [licence Apache 2.0](LICENSE). En soumettant une contribution, vous
acceptez qu'elle soit placée sous les mêmes conditions, comme le prévoit la section 5 de la licence.
Il n'y a pas d'accord de contribution séparé à signer.

## Conduite

Toute personne qui participe suit le [Code de conduite](CODE_OF_CONDUCT.md).
