# Audit approfondi — code, sécurité, documentation

**28 août 2026, 10h28** · *English version: [`2026-08-28_10_28_20_in_depth_code_security_doc_audit.en.md`](../en/2026-08-28_10_28_20_in_depth_code_security_doc_audit.en.md)*

## Note globale : **8,0 / 10** — en baisse depuis 8,5

**La baisse n'est pas une dégradation du produit. C'est la perte d'une vérification.** Le 25 août,
l'audit avait établi que rien n'avait jamais tourné sur une machine ; le pipeline GitLab écrit dans
la foulée avait fermé ce trou, et l'audit du 26 en avait tenu compte. Le projet a depuis migré vers
GitHub, et **le pipeline porté n'a jamais été vert une seule fois**. Le terrain n'a pas empiré : la
preuve a été remise à zéro par la bascule, et elle n'est pas encore reconstituée.

C'est la distinction que le prompt exige de nommer. Ce n'est pas « un audit précédent avait noté ce
qu'il n'avait pas mesuré » ; c'est « ce qui était mesuré ne l'est plus ».

| Domaine | Note | Mouvement |
|---|---|---|
| Documentation & Architecture | **9,0** | ↑ |
| Sécurité & Cryptographie | **9,0** | ↑ |
| Qualité du code | **8,5** | = |
| Conformité & Standards | **8,5** | = |
| **Vérification réellement exécutée** | **5,0** | ↓↓ |

---

## 1. Ce que j'ai exécuté

Tout ce qui suit a été lancé, pas relu.

| Contrôle | Commande | Résultat |
|---|---|---|
| Suites JVM | `./gradlew build` | **1371 tests, 0 échec, 0 ignoré** (276 fichiers de résultats) |
| Suites Angular | `npx ng test --no-watch` | **146 tests, 23 fichiers, 0 échec** |
| Liens relatifs | `scripts/check-doc-links.py` | **616 liens, 0 cassé** |
| Dérive C4 | empreinte de `workspace.dsl` | **en phase avec les diagrammes** |
| Secrets | `gitleaks` + baseline | **propre** — après correction, §4 |
| Parité bilingue | comparaison des arbres | **12 / 12**, aucun orphelin |
| Registre ADR | `ls decisions/` | **0001 → 0016**, dans les deux langues |
| Tirage de restauration | `scripts/restore-drill.sh` | **passé**, assertions comprises |

## 2. Tester ses propres tests

Le prompt le pose comme non négociable, et c'est là que ce projet a déjà livré trois assertions
incapables d'échouer. Quatre mutations, chacune consistant à casser le code et à exiger que le test
tombe.

| Mutation appliquée | Attendu | Obtenu |
|---|---|---|
| `IssueFingerprint` : permuter `type` et `identifier` | échec | **1 test échoue** — *« a known finding has a known fingerprint »* |
| `SecretCipher` : retirer la liaison de contexte (AAD) | échec | **3 tests échouent**, dont les deux cas « ne doit pas déchiffrer » |
| `SealedEnvelope` : `HKDF_INFO` v1 → v2 | échec | **1 test échoue** — l'enveloppe scellée par un build antérieur ne s'ouvre plus |
| `AuditLogController` : retirer `@RequiresSecurityLead` | échec | **2 tests échouent** — couverture d'autorisation **et** maille route |
| `.gitleaks.toml` : injecter un secret aléatoire (`openssl rand -hex 24`) | détection | **détecté** |

La première mutation mérite d'être soulignée : c'est **exactement** celle qui, le 26 août, ne
faisait échouer aucun test. Le vecteur littéral épinglé depuis a fermé le trou, et il le prouve.

La quatrième produit un message qui dit quoi faire — *« résolvez une Visibility, appelez un helper
nommé requireVisible…, ou portez un garde de rôle ; et si la route ne nomme réellement aucune
cible, ajoutez-la à NAMES_NO_TARGET avec la raison »*. Une règle de sécurité qui n'explique pas
comment s'y conformer est une règle qu'on contourne.

## 3. Le constat central : la vérification n'a pas suivi la migration

**Trois faits, mesurés.**

**a. Le pipeline GitHub n'a jamais été vert.** Une seule exécution, et elle a échoué :
`accepts at most 1 arg(s), received 2`. La cause était un bug de portage — sur GitLab le premier
argument de `docker create` est le *nom du conteneur*, consommé par un `shift` ; en passant à
`docker run --rm` le nom disparaît et les mots `report` et `verdict` sont partis dans `"$@"`. Le
commentaire d'origine ayant survécu, le code se lisait comme intentionnel. Corrigé
(`8a7f1b25`), reproduit en local — syft trouve 159 composants, grype 5 constats corrigibles — et
testé par mutation sur le seuil : `--fail-on high` → 0, `--fail-on medium` → 2, le tableau
s'imprimant avant l'échec dans les deux cas. **Mais le correctif n'est pas poussé.**

**b. Le nocturne ne peut pas se déclencher.** GitHub n'exécute un workflow planifié que depuis la
**branche par défaut**. `main` est à `949f5130`, **75 commits en retard**, et `nightly.yml` n'y
figure pas. Les quatre jobs nocturnes — `databases`, `dockerfiles`, `e2e`, `restore` — sont
déclarés et aucun ne peut partir. C'est le mode de défaillance de GitLab qui se répète pour une
raison différente : là-bas il manquait un schedule dans les réglages, ici il manque la branche.
Le `cron:` dans le fichier a supprimé une cause d'oubli, pas toutes.

**c. Les workflows fossiles sont sur la branche par défaut.** `main` porte encore `ci.yml` et
`release.yml` d'avant le portage, avec `on: pull_request`. **La prochaine pull request lance le
pipeline périmé.** L'étape 0 du plan de migration — « on les archive avant le premier push, jamais
après » — a été faite dans l'historique mais `main` ne l'a jamais reçue.

Les trois se referment d'un seul geste : `main` en fast-forward jusqu'à la tête de `develop`. Le
push utilise les workflows de la ref poussée, donc l'opération se soigne elle-même.

**Ce qui reste non exécuté et doit être compté comme tel :** `integrationTestAll` (40 min, deux
moteurs réels) n'a pas été lancé dans cet audit ; `release.yml` n'a jamais tourné, donc l'identité
cosign GitHub et la permission `id-token: write` sont **affirmées, non exécutées**. Une signature
que personne n'a produite est une signature qui ne marche pas.

## 4. Un constat produit par cet audit, et il vient de moi

`gitleaks` avec la baseline a trouvé **une fuite**, introduite par `3fb0519d` — mon propre commit,
une étape plus tôt : la clé du tirage de restauration, entropie 4,67, règle `generic-api-key`. Une
valeur dont le clair dit « not-a-secret » ne se lit pas ainsi par un scanner.

Corrigée par liste blanche **par valeur** dans `.gitleaks.toml`, à côté de la clé de vecteur KAT,
et non par empreinte de baseline : une empreinte épingle commit + fichier + ligne et ne survit pas
à un rebase.

Un détail annexe mérite d'être noté à l'actif du produit. L'ancienne valeur décodait en **30**
octets, pas 32, et l'application a démarré. Ce n'est pas un défaut : `EncryptionKey` n'accepte une
clé brute que sous forme de base64 de *exactement* 32 octets, si bien qu'une valeur de 30 octets
tombe dans la branche *passphrase* et est étirée par scrypt (N=2¹⁵). **Le design a absorbé mon
erreur correctement.**

## 5. Sécurité — ce que j'ai pu confirmer

**Bac à sable des scanners.** `ContainerRunner` applique `withCapDrop(Capability.values())` —
toutes les capacités, pas une liste —, `no-new-privileges`, rootfs en lecture seule, tmpfs
`rw,noexec,nosuid` pour `/tmp` et `HOME`, plafonds mémoire / nanoCPU / PID, et `NetworkMode("none")`
sauf demande explicite. Et surtout : `ContainerHardeningTest` **épingle ces réglages**, donc un
refactor ne peut pas les retirer en silence.

**Isolation de l'agent.** `./gradlew :vectispire-agent:dependencies --configuration runtimeClasspath`
→ **zéro** occurrence de mysql, postgres, jdbc, hibernate ou spring-data-jpa. Aucune référence à
`ENCRYPTION_KEY` dans sa configuration. L'étanchéité est réelle, pas documentaire.

**Argon2id.** `m=19456, t=2, p=1`, format PHC — et un test épingle le préfixe
`$argon2id$v=19$m=19456,t=2,p=1$`. `needsRehash` compare aux paramètres courants, donc relever le
coût ne casse pas l'existant.

**Conformité.** `ComplianceEngine` commute bien sur **7** catégories et projette sur **6**
référentiels — 24 contrôles. La formulation « un évaluateur, six cartographies » est exacte.

## 6. Recommandations, par ordre d'urgence

| # | Action | Vérifié comment |
|---|---|---|
| 1 | **Pousser `develop`, puis `main` en fast-forward.** Ferme les trois constats du §3 d'un geste. | Bloqué : GitHub refuse l'écriture aux deux clés de la machine. `--dry-run` sur `asmolabs_id_ed25519` → *Permission denied* ; sur `id_ed25519` → *denied to Asmo1973*. **Action côté compte, pas côté code.** |
| 2 | **Épingler les cinq `uses:` à un SHA.** `actions/{checkout,setup-java,cache,upload-artifact,download-artifact}` sont tous sur un tag flottant, et `release.yml` signe avec eux. Un tag est déplaçable ; une signature produite par une action remplacée reste valide et ne prouve plus rien. | Mesuré : `grep -hoE 'uses: [^ ]+' .github/workflows/*.yml` → 5 actions, 0 SHA |
| 3 | **Faire tourner `release.yml` en `workflow_dispatch` sur un tag d'essai.** L'identité cosign et `id-token: write` sont affirmées et jamais exécutées ; l'échec se produirait au moment de la publication. | Affirmé, non exécuté |
| 4 | **Lancer `integrationTestAll` avant toute release.** Le nocturne ne peut pas le faire (§3b), donc la portabilité multi-moteurs n'est vérifiée par personne aujourd'hui. | Non exécuté dans cet audit |
| 5 | Nettoyer les défauts triplement imbriqués — `${VECTISPIRE_PASSWORD_LOGIN:${VECTISPIRE_PASSWORD_LOGIN:${VECTISPIRE_PASSWORD_LOGIN:true}}}` sur six propriétés d'`application.yaml`. Sans effet, mais c'est le genre de résidu qui fait douter du reste. | Mesuré par lecture ; aucun effet fonctionnel |

## 7. Ce que je n'ai pas mesuré

- `integrationTestAll` — PostgreSQL et MySQL réels, 40 minutes.
- La suite Playwright — elle exige un plan de contrôle démarré ; le nocturne devait s'en charger.
- Le comportement sous mauvaise `ENCRYPTION_KEY` — le tirage de restauration le nomme comme son
  manque assumé (§4 de `BACKUP_AND_RESTORE`), et cet audit ne l'a pas comblé.
- Toute exécution réelle sur un runner GitHub : je n'ai pas accès en écriture au dépôt.
