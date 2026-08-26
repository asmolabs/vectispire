# Rapport d'Audit Approfondi : Documentation, Code Source & Sécurité

* **Projet :** Vectispire — ASPM & Plan de Contrôle de Sécurité Logicielle
* **Date :** 26 août 2026, 16:10
* **Commit audité :** `f92f192d` (`develop`)
* **Périmètre :** les cinq axes de [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md)

> **Onzième passage, quelques heures après le dixième.** Une partie de ce rapport vérifie donc
> ma propre remédiation, ce qui est le pire angle possible pour trouver un défaut. J'ai orienté
> l'effort ailleurs : la cryptographie, la chaîne d'audit, le contrat d'empreinte et les moteurs
> réglementaires — nommés dans le prompt depuis dix passages, jamais **sondés**.

---

## 0. Ce qui a été exécuté

| commande | résultat |
|---|---|
| `./gradlew check` | **vert** |
| `./gradlew integrationTestAll --rerun-tasks` | **vert sur les trois moteurs**, 1 min 59 s |
| `npx ng test --no-watch` | **23 fichiers, 146 tests** |
| `python3 scripts/check-doc-links.py` | 570 liens, 0 cassé |

**Un piège de méthode, rencontré dans ce passage même.** Le premier `integrationTestAll` a rendu
« BUILD SUCCESSFUL in 549ms » : Gradle l'a jugé à jour et **n'a rien exécuté**. Compter ce vert-là
comme une campagne aurait été exactement l'erreur que l'axe 5 interdit. D'où le `--rerun-tasks`.
Quiconque lit un vert de campagne doit d'abord regarder la durée.

Non exécuté, et compté comme tel : la suite Playwright, et la joignabilité à travers `docker:dind`.

---

## 1. Synthèse

| Domaine | Note | Ce qui la fixe |
|---|:---:|---|
| **Documentation & Architecture** | **9,2 / 10** | ADR-0001 a reçu son raisonnement ; le contrôle C4 reste une empreinte, pas une régénération |
| **Sécurité & Cryptographie** | **8,8 / 10** | La crypto dépasse ce que le prompt revendique ; la 24ᵉ route est fermée et prouvée |
| **Qualité du Code** | **8,2 / 10** | **Le contrat d'empreinte n'est protégé par aucun test** — démontré, pas supposé |
| **Conformité & Standards** | **9,3 / 10** | Six cadres implémentés là où le prompt en annonce quatre |
| **Vérification exécutée** | **8,5 / 10** | Le *schedule* existe ; aucun nocturne n'est encore passé au vert |

---

## 2. Le constat de ce passage : 🟠 C1

**L'empreinte d'un constat est un contrat de données, et rien ne l'épingle.**

Le prompt le dit depuis le premier jour : *« tout ce qui entre dans l'empreinte est un contrat ;
le changer résout et recrée chaque constat, en perdant tout le triage »*. `IssueFingerprintTest`
couvre cette règle par des propriétés **relationnelles** : la même entrée donne la même sortie, la
version est exclue, deux cibles séparent, un purl vide retombe sur le nom du paquet. Toutes vraies,
toutes utiles.

**Aucune ne survit à la question : est-ce que la valeur a changé ?**

J'ai réordonné deux champs dans `IssueFingerprint.of` — `target` et `type` permutés, rien d'autre :

```java
Digests.sha256Fields(
        input.type().wireName(),          // permuté
        input.target().fingerprintKey(),  // permuté
        input.identifier(), …)
```

`./gradlew :vectispire-common:test --tests '*IssueFingerprint*'` → **BUILD SUCCESSFUL**.

Toutes les propriétés relationnelles tiennent encore : la fonction reste déterministe, exclut
toujours la version, sépare toujours les cibles. Et **chaque empreinte du parc a changé**. En
production, ce commit résout silencieusement tous les constats ouverts et les recrée à neuf :
triage perdu, exemptions perdues, dates de revue perdues, sans une exception ni une ligne de
journal — et un tableau de bord qui a l'air plus propre après.

C'est le même défaut de forme que `WebhookAuthenticity`, qui *a* son vecteur HMAC épinglé
(`6e9ef29b…`). Ici il en manque un.

**Correctif :** un test qui affirme une valeur littérale pour une entrée fixe. Trois lignes. Il
échouera au prochain changement d'algorithme — et c'est tout l'intérêt : la migration devient une
décision consciente au lieu d'un effet de bord.

---

## 3. Sécurité — 8,8, et la crypto vaut mieux que sa description

Ce que le prompt revendique est vrai, et **incomplet**.

| revendiqué | mesuré |
|---|---|
| Argon2id | 19 MiB, **t=2, p=1**, sel 16 o, empreinte 32 o, format PHC — les paramètres voyagent avec l'empreinte, donc relever le coût n'invalide pas l'existant |
| AES-256-GCM | nonce **12 o**, tag **128 bits**, **AAD de contexte**, format préfixé `v2:` |
| *(non mentionné)* | **`SealedEnvelope` : X25519 + HKDF + GCM** — chiffrement hybride vers une clé éphémère de l'agent, pour que le plan de contrôle ne soit pas dans la frontière de confiance du secret |

Un dossier d'architecture qui sous-vend sa propre cryptographie est un problème mineur, mais c'en
est un : un auditeur externe note ce qui est écrit.

**La 24ᵉ route est fermée et la fermeture est prouvée.** `GET /inventory/versions` joint désormais
le scan et filtre sur la `Visibility`. Le test correspondant échoue quand on retire le filtre
(`expected:<1> but was:<2>`) — vérifié en le retirant.

**Ce qui reste :** `AuthorizationCoverageTest` travaille toujours à la maille contrôleur. C'est
justifié — le filtrage passe par des méthodes d'aide privées qu'aucune regex ne suit — mais la
règle demeure plus grossière que la classe de défaut qu'elle surveille.

---

## 4. Qualité du Code — 8,2

Outre C1, la remédiation du dixième passage tient : `SecurityScorecardService` répond par une
existence indexée au lieu de lire tous les scans, `syncThreatIntel` filtre en SQL et joint en un
lot. La troisième lecture complète du scorecard subsiste, **et le code dit pourquoi** — la question
porte sur l'ensemble des cibles visibles, qu'aucune requête dérivée ne sait exprimer.

### 🟡 C2 — deux cas end-to-end ne peuvent pas échouer

`e2e/vex-triage.spec.ts` contient deux tests dont l'assertion entière est :

```ts
const body = page.locator('body');
await expect(body).toBeVisible();
```

Un `body` est visible sur une page d'erreur, sur une page blanche, sur une redirection vers la
connexion. Ces deux cas comptent dans « 11 tests navigateur » et n'en vérifient aucun.

### 🟡 C3 — couverture frontale : 16 pages sur 28

Cinq specs ajoutées depuis le dixième passage, sur les pages qui *calculent*. Douze pages restent
sans spec, délibérément : elles affichent une réponse HTTP telle quelle, et un test qui les monte
prouve que le client HTTP fonctionne.

---

## 5. Conformité — 9,3

Le prompt annonce quatre cadres. `ComplianceFramework` en énumère **six** : `NIS_2`, `ISO_27001`,
`EU_CRA`, `DORA`, `PCI_DSS`, `SOC_2`, l'OWASP Top 10 vivant dans son propre contrôleur. Les formats
de chaîne d'approvisionnement sont produits, et **SPDX est refusé et consigné** (ADR-0016) plutôt
que revendiqué à vide.

---

## 6. Vérification — 8,5

Le *schedule* nocturne **existe** — je l'avais nié dans le dixième rapport, par déduction et non
par mesure ; la correction y est visible plutôt qu'effacée.

Ce qui reste non démontré : **aucun pipeline nocturne n'est encore passé au vert**. Les deux
exécutions du 26 août étaient manuelles et ont trouvé deux vrais défauts, corrigés depuis.
Le premier nocturne vert sera la preuve.

---

## 7. Recommandations

| # | Action | Vérifié comment |
|---|---|---|
| 🟠 1 | Épingler un vecteur littéral dans `IssueFingerprintTest` | **mesuré** : deux champs permutés, tous les tests passent |
| 🟡 2 | Donner aux deux cas VEX une assertion capable d'échouer | mesuré : leur assertion est `body` visible |
| 🟡 3 | Décrire `SealedEnvelope` dans la vue sécurité et dans le prompt | mesuré : X25519+HKDF présent, absent de la doc |
| 🟡 4 | Faire porter la règle d'autorisation sur une convention de nommage des aides | argumenté, non implémenté |
| ℹ️ 5 | Lire la **durée** d'un `integrationTestAll` avant de croire son vert | rencontré dans ce passage : 549 ms |
