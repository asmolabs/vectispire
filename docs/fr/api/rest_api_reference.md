# Référence Complète de l'API REST Vectispire

Ce document constitue la référence officielle et exhaustive des interfaces de programmation REST exposées par le Control Plane **Vectispire** (v4.1.0).

---

## 🔒 Sécurité et Authentification

L'API Vectispire utilise trois mécanismes d'authentification selon le type d'appelant :

### 1. Jeton de Session Utilisateur (`Bearer JWT`)
* **En-tête** : `Authorization: Bearer <token>`
* **Utilisation** : Interface Web Angular, sessions d'utilisateurs interactives.
* **Obtention** : Via `POST /api/v1/auth/login` (avec support éventuel du 2FA/TOTP via `POST /api/v1/auth/mfa/verify`).

### 2. Clé d'Agent de Scan (`X-Agent-Key`)
* **En-tête** : `X-Agent-Key: <agent_key>`
* **Utilisation** : Protocoles d'agents distants distribués (`/api/v1/agent/**`).

### 3. Clé d'API Programmatique (`X-API-Key`)
* **En-tête** : `X-API-Key: <api_key>`
* **Utilisation** : Pipelines CI/CD (GitHub Actions, GitLab CI), intégrations SIEM et scripts d'automatisation.

---

## 🧭 Résumé des Endpoints

| Domaine | Méthode | Endpoint | Auth | Description |
|---|---|---|---|---|
| **Auth** | `POST` | `/api/v1/auth/login` | Public | Authentification utilisateur (identifiants / mot de passe). |
| **Auth** | `GET` | `/api/v1/auth/methods` | Public | Découverte des méthodes d'authentification (Password, SSO OIDC). |
| **Auth** | `POST` | `/api/v1/auth/session/exchange` | Public | Échange du cookie de redirection SSO contre un token de session. |
| **Auth** | `POST` | `/api/v1/auth/mfa/verify` | Public | Validation du challenge MFA / TOTP. |
| **Auth** | `POST` | `/api/v1/auth/mfa/setup` | Compte | Initialisation de la double authentification (génération du secret TOTP). |
| **Auth** | `POST` | `/api/v1/auth/mfa/enable` | Compte | Activation définitive du MFA après saisie d'un premier code. |
| **Auth** | `POST` | `/api/v1/auth/mfa/disable` | Compte | Désactivation du MFA avec validation par code. |
| **Surface d'Attaque** | `GET` | `/api/v1/attack-surface` | Compte | Synthèse globale de la surface d'attaque et routes à haut risque. |
| **Surface d'Attaque** | `DELETE` | `/api/v1/attack-surface` | Compte | Purge globale de l'inventaire des endpoints et contrats. |
| **Surface d'Attaque** | `GET` | `/api/v1/repositories/{id}/apis` | Compte | Inventaire des routes découvertes et contrats OpenAPI d'un dépôt. |
| **Surface d'Attaque** | `DELETE` | `/api/v1/repositories/{id}/apis` | Compte | Purge des endpoints et contrats d'un dépôt spécifique. |
| **Surface d'Attaque** | `GET` | `/api/v1/repositories/{id}/apis/export/openapi` | Compte | Export du schéma OpenAPI 3.0 synthétisé à partir du code source. |
| **Dépôts Git** | `GET` | `/api/v1/repositories` | Compte | Liste des dépôts surveillés avec état du dernier scan. |
| **Dépôts Git** | `POST` | `/api/v1/repositories` | Admin | Enregistrement d'un nouveau dépôt Git à analyser. |
| **Dépôts Git** | `PATCH` | `/api/v1/repositories/{id}` | Admin | Mise à jour des paramètres, branches, cron ou clés SSH d'un dépôt. |
| **Dépôts Git** | `POST` | `/api/v1/repositories/{id}/scan` | Admin | Déclenchement d'une analyse de sécurité immédiate sur le dépôt. |
| **Dépôts Git** | `DELETE` | `/api/v1/repositories/{id}` | Admin | Suppression d'un dépôt et purge en cascade de ses analyses. |
| **Scans** | `GET` | `/api/v1/scans` | Compte | Historique des analyses de sécurité avec filtres par cible. |
| **Scans** | `GET` | `/api/v1/scans/{id}` | Compte | Détail d'un scan et inventaire des constats (findings) observés ; `examinedTypes` nomme les étapes intégrées qui ont produit (`null` : non enregistré, jamais « rien examiné »). |
| **Scans** | `GET` | `/api/v1/scans/{id}/sbom` | Compte | Téléchargement du SBOM brut, tel que Syft l'a produit (JSON natif). Le document CycloneDX-avec-VEX généré est `/api/v1/cyclonedx` — voir la [décision 0016](../../architecture/fr/decisions/0016-no-spdx-document.md). |
| **Vulnérabilités** | `GET` | `/api/v1/issues` | Compte | Consultation du backlog des vulnérabilités actives et résolues. |
| **Vulnérabilités** | `GET` | `/api/v1/issues/{id}` | Compte | Consultation détaillée d'une vulnérabilité et de son historique. |
| **Vulnérabilités** | `POST` | `/api/v1/issues/{id}/triage` | Lead/Admin | Décision de triage (Acceptation de risque, Faux-positif, Atténuation). |
| **Conformité** | `GET` | `/api/v1/compliance/summary` | Compte | Synthèse de conformité multi-référentiels (NIS2, ISO 27001, CRA, SOC2). |
| **Conformité** | `GET` | `/api/v1/compliance/frameworks/{fw}` | Compte | Évaluation détaillée des exigences pour un référentiel réglementaire. |
| **Conformité** | `GET` | `/api/v1/compliance/export.pdf` | Compte | Téléchargement du rapport exécutif de conformité au format PDF. |
| **Conformité** | `GET` | `/api/v1/compliance/evidence-bundle.zip` | Compte | Export du bundle d'audit scellé (preuves cryptographiques SHA-256). |
| **Scorecards** | `GET` | `/api/v1/scorecards/repositories/{id}` | Compte | Scorecard et note de posture de sécurité d'un dépôt. |
| **Scorecards** | `GET` | `/api/v1/scorecards/containers/{id}` | Compte | Scorecard et note de sécurité d'une image conteneur. |
| **Scorecards** | `GET` | `/api/v1/scorecards/global` | Compte | Scorecard global consolidé pour l'ensemble de l'organisation. |
| **Scorecards** | `GET` | `/api/v1/scorecards/repositories/{id}/badge` | Compte | Un badge public est-il publié pour ce dépôt, et à quelle URL. |
| **Scorecards** | `POST` | `/api/v1/scorecards/repositories/{id}/badge` | Écriture | Publie le badge. Sa note devient alors lisible par quiconque détient l'URL. |
| **Scorecards** | `DELETE` | `/api/v1/scorecards/repositories/{id}/badge` | Écriture | Le révoque. Tout README portant l'ancienne URL répond désormais 404. |
| **Scorecards** | `GET` | `/api/v1/scorecards/badges/{token}.svg` | Public | Badge SVG dynamique pour affichage dans les fichiers README Git. |
| **Preuve de processus** | `GET` | `/api/v1/gate/verdicts` | Gouvernance | Les réponses de la barrière, la plus récente d'abord, avec un curseur. Un refus est la seule preuve qu'un contrôle s'exécute : « toutes les cibles passent » ne distingue pas un parc propre d'une barrière qui n'a jamais rien bloqué. |
| **Preuve de processus** | `GET` | `/api/v1/exceptions` | Compte | Acceptations de risque et rejets, avec qui a décidé, sur quelle justification, jusqu'à quand, et quand la ligne a été rouverte pour la dernière fois. |
| **Preuve de processus** | `POST` | `/api/v1/exceptions/{issueId}/reviews` | Responsable/Admin | Enregistre qu'une exception a été revue — confirmée, prolongée ou révoquée. Une confirmation ne change rien, et c'est tout l'intérêt : c'est la seule chose qui fasse de « quelqu'un a regardé » un fait daté. |
| **Preuve de processus** | `GET` | `/api/v1/remediation/distribution` | Compte | Les délais par la queue de distribution plutôt que par la moyenne : part dans le délai, médiane, 90e centile, retard ouvert et plus ancien élément. |
| **Preuve de processus** | `GET` | `/api/v1/rule-sets/coverage` | Gouvernance | Quels langages les règles d'analyse de code installées atteignent, et quels écosystèmes du parc elles n'atteignent pas. Ce qui rend lisible un compte de constats à zéro. |
| **SMSI** | `GET` | `/api/v1/compliance/soa` | Gouvernance | La déclaration d'applicabilité par cadre, chaque contrôle confronté à son état mesuré (ISO 27001, clause 6.1.3 d). |
| **SMSI** | `GET` | `/api/v1/compliance/soa/{framework}` | Gouvernance | La déclaration d'un cadre, ligne par ligne, avec l'écart entre ce qui est affirmé et ce qui est mesuré. |
| **SMSI** | `GET` | `/api/v1/compliance/soa/reviews/overdue` | Gouvernance | Les déclarations dont la date de revue est passée, tous cadres confondus. |
| **SMSI** | `PUT` | `/api/v1/compliance/soa/{framework}/{controlId}` | Responsable/Admin | Écrit ou révise une ligne. Une exclusion demande une justification ; une preuve détenue ailleurs doit dire où. |
| **SMSI** | `GET` | `/api/v1/compliance/scope` | Gouvernance | Le périmètre certifié, combien d'actifs il déclare, et combien portent une preuve courante. |
| **SMSI** | `PUT` | `/api/v1/compliance/scope/repositories/{id}` | Responsable/Admin | Marque un dépôt comme dans ou hors du périmètre certifié. |
| **SMSI** | `PUT` | `/api/v1/compliance/scope/containers/{id}` | Responsable/Admin | Marque une image comme dans ou hors du périmètre certifié. |
| **OWASP** | `GET` | `/api/v1/owasp/coverage` | Compte | Le Top 10 répondu par règle, en quatre états. Sept catégories ne sont couvertes par aucun scanner ici, et cette route le dit au lieu de les montrer vertes. |
| **Plugins** | `GET` | `/api/v1/plugins` | Compte | Plugins enregistrés, chacun avec le manifeste qu'il exécute (image épinglée par digest, langages, arguments, exception réseau). |
| **Plugins** | `POST` | `/api/v1/plugins` | Gouverneur | Enregistrer un plugin à partir de son manifeste. L'id n'est jamais réutilisé. |
| **Plugins** | `PUT` | `/api/v1/plugins/{id}` | Gouverneur | Un nouveau manifeste sous le même id — une nouvelle version d'image garde le triage de chaque issue. |
| **Plugins** | `PUT` | `/api/v1/plugins/{id}/enabled` | Gouverneur | Activer ou désactiver un plugin partout, en gardant ses activations. |
| **Plugins** | `GET` | `/api/v1/plugins/{id}/projects` | Gouvernance | Les projets pour lesquels un plugin est activé. |
| **Plugins** | `GET` | `/api/v1/projects/{id}/plugins` | Gouvernance | Les plugins activés pour un projet. |
| **Plugins** | `PUT` / `DELETE` | `/api/v1/projects/{id}/plugins/{pluginId}` | Lead/Admin | Activer ou désactiver un plugin pour un projet. |
| **Import SARIF** | `GET` / `POST` | `/api/v1/sarif-sources` | Gouvernance / Gouverneur | Les sources internes déclarées : une clé d'intégration, un projet ou un dépôt, les types qu'elle peut livrer (`sarif`, `coverage`, `test_report` ; absent vaut `sarif`) et, pour le SARIF, les outils. |
| **Import SARIF** | `PUT` / `DELETE` | `/api/v1/sarif-sources/{id}[/enabled]` | Gouverneur | Suspendre, reprendre ou supprimer une source déclarée. |
| **Import SARIF** | `POST` | `/api/v1/repositories/{id}/sarif-imports` | Clé `sarif_import` | Déposer le rapport SARIF 2.1.0 d'une source déclarée dans le backlog d'un dépôt ; voir [Plugins et imports SARIF](../../../docs-site/administration/plugins.fr.md). |
| **Import SARIF** | `GET` | `/api/v1/repositories/{id}/sarif-imports` | Compte | Les derniers imports du dépôt, avec l'empreinte de leur document et ce que chacun a fait. |
| **Import de rapports** | `POST` | `/api/v1/repositories/{id}/coverage-imports` | Clé `report_import` | Enregistrer le rapport de couverture d'une source déclarée pour un dépôt, son format déclaré dans `?format=` (`jacoco`, `cobertura`, `lcov`) ; voir [Importer des rapports de couverture et de tests](../../../docs-site/administration/plugins.fr.md#importer-des-rapports-de-couverture-et-de-tests). |
| **Import de rapports** | `POST` | `/api/v1/repositories/{id}/test-report-imports` | Clé `report_import` | Enregistrer le rapport JUnit d'une source déclarée — un document XML ou un zip de plusieurs — pour un dépôt. |
| **Import de rapports** | `GET` | `/api/v1/repositories/{id}/coverage-imports`, `/test-report-imports` | Compte | Les cinquante derniers imports de chaque type du dépôt, avec leurs chiffres et l'empreinte de leur document. |
| **Modèles de checklist** | `GET` | `/api/v1/checklist-templates` | Gouvernance | Chaque modèle des checklists de l'organisation, avec ses versions et leur état (`draft`, `published`, `retired`) ; [décision 0032](../../architecture/fr/decisions/0032-security-checklists.md). |
| **Modèles de checklist** | `POST` | `/api/v1/checklist-templates/{slug}/versions` | Responsable/Admin | Importer le classeur — le `.xlsx` en corps brut, 10 Mo — comme version suivante du modèle, un brouillon ; un nouveau slug crée le modèle (`?name=`). Jamais publié en une étape. |
| **Modèles de checklist** | `GET` | `/api/v1/checklist-templates/{slug}/versions/{ordinal}/preview` | Gouvernance | La disposition que le lecteur propose d'après la structure du classeur, celle confirmée, les cellules d'une feuille, et l'appariement de chaque ligne avec la version précédente. |
| **Modèles de checklist** | `PUT` | `/api/v1/checklist-templates/{slug}/versions/{ordinal}/layout` | Responsable/Admin | Confirmer la disposition d'un brouillon (`?revision=` : celle que l'éditeur a lue ; un brouillon modifié depuis est refusé, 409) et associer ses mots de réponse ; les lignes sont lues d'après elle. |
| **Modèles de checklist** | `PUT` | `/api/v1/checklist-templates/{slug}/versions/{ordinal}/pairs` | Responsable/Admin | Sur `?revision=`, celle que l'éditeur a lue : apparier à la main une ligne reformulée avec celle de la version précédente, pour que la réponse d'un projet la suive, à confirmer. |
| **Modèles de checklist** | `POST` | `/api/v1/checklist-templates/{slug}/versions/{ordinal}/derive` | Responsable/Admin | Un nouveau brouillon à partir d'une version publiée : même classeur, même disposition, mêmes lignes. |
| **Modèles de checklist** | `POST` | `/api/v1/checklist-templates/{slug}/versions/{ordinal}/publish` | Responsable/Admin | Publier un brouillon à la `revision` relue. Double contrôle activé : pas par l'un des comptes qui l'ont écrit (409). |
| **Modèles de checklist** | `POST` | `/api/v1/checklist-templates/{slug}/versions/{ordinal}/retire` | Responsable/Admin | Ne plus proposer une version publiée pour de nouvelles checklists — double contrôle activé, pas par l'un de ses auteurs — ou écarter un brouillon. |
| **Checklists de projet** | `GET` | `/api/v1/projects/{id}/checklists` | Compte | Chaque révision de la checklist du projet, la plus récente d'abord. Pour qui voit le projet **entier** — tout, le projet attribué comme tel, ou chacun de ses dépôts ; tout autre, et un projet qui n'existe pas, reçoit un 404 dans les mêmes mots ([décision 0032](../../architecture/fr/decisions/0032-security-checklists.md) §8). |
| **Checklists de projet** | `GET` | `/api/v1/projects/{id}/checklists/offered` | Compte | Les versions de modèle publiées sur lesquelles la checklist du projet peut être ouverte ou déplacée. |
| **Checklists de projet** | `POST` | `/api/v1/projects/{id}/checklists` | Écriture | Ouvrir la checklist du projet sur une version publiée — `template` (slug), `version` — ou la faire passer à une autre : une nouvelle révision, les réponses reportées, courantes là où la ligne n'a pas changé et à confirmer là où elle a changé. `edition` est celle de la révision la plus récente telle que lue, absente quand aucune n'a été vue. |
| **Checklists de projet** | `GET` | `/api/v1/projects/{id}/checklists/{revision}` | Compte | Une révision : ses lignes avec leur réponse courante, leurs preuves et ce qui empêche chacune d'être soumise (`problems`), ses auteurs, son `edition`. |
| **Checklists de projet** | `GET` | `/api/v1/projects/{id}/checklists/{revision}/items/{itemId}/history` | Compte | Chaque réponse donnée sur la ligne, avec son auteur et son instant, jamais modifiée, et chaque preuve. |
| **Checklists de projet** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/items/{itemId}/answers` | Écriture | Répondre à une ligne d'un brouillon (`yes`, `no`, `not_applicable` ; un commentaire pour les deux derniers) à l'`edition` lue. Une ligne modifiée depuis est refusée (409 `checklist-line-changed`). |
| **Checklists de projet** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/items/{itemId}/confirmation` | Écriture | Confirmer une réponse reportée sur une ligne qui a changé, au nom de l'appelant. |
| **Checklists de projet** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/items/{itemId}/evidence/links` | Écriture | Joindre un lien comme preuve — `https:` ou `http:`, 2 000 caractères — avec le jour où le travail a été fait (`performedOn`). |
| **Checklists de projet** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/items/{itemId}/evidence/files` | Écriture | Joindre un fichier comme preuve : le corps brut, 25 Mo, son `Content-Type` conservé et jamais cru ; `name`, `performedOn` et `edition` en paramètres. |
| **Checklists de projet** | `GET` | `/api/v1/projects/{id}/checklists/{revision}/evidence/{evidenceId}/file` | Compte | Le fichier d'une preuve, toujours en pièce jointe, `application/octet-stream` et `nosniff`, quel que soit son type déclaré. |
| **Checklists de projet** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/evidence/{evidenceId}/withdrawal` | Écriture | Retirer une preuve d'un brouillon ; la ligne reste, datée et attribuée. |
| **Checklists de projet** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/submission` | Écriture | Soumettre un brouillon à l'`edition` relue : chaque ligne répondue, commentée si négative, prouvée là où un oui le demande, aucune à confirmer (409 `checklist-incomplete` nomme les lignes). |
| **Checklists de projet** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/return` | Écriture | Renvoyer une révision soumise à ses auteurs avec une `reason` : de nouveau un brouillon. |
| **Checklists de projet** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/sign-off` | Écriture | Approuver une révision soumise — un administrateur, un CISO ou un référent sécurité, 403 sinon. Double contrôle activé : aucun de ses auteurs — qui l'a ouverte, a répondu, reporté, confirmé, prouvé ou soumis (409 `checklist-four-eyes`). |
| **Checklists de projet** | `POST` | `/api/v1/projects/{id}/checklists/{revision}/reopen` | Écriture | La révision suivante d'une révision approuvée, sur la même version, chaque réponse reportée comme courante ; celle approuvée n'est jamais modifiée. |
| **Agent** | `GET` | `/api/v1/agent/plugins/{id}/{digest}` | Clé d'agent | Le manifeste qu'une tâche a nommé, par id et digest ; l'agent refuse celui qui ne correspond pas au digest. |
| **Cryptographie** | `GET` | `/api/v1/crypto/public-key.pub` | Public | Clé publique ECDSA pour vérification des signatures Cosign / Sigstore. |

---

## 🛠️ Exemples d'Appels cURL

### 1. Connexion et Récupération du Jeton
```bash
curl -X POST "https://vectispire.example.com/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "MonSuperMotDePasse"}'
```

### 2. Déclenchement d'une Analyse de Dépôt
```bash
curl -X POST "https://vectispire.example.com/api/v1/repositories/1/scan" \
  -H "Authorization: Bearer <VOTRE_JWT_TOKEN>"
```

### 3. Consultation de la Surface d'Attaque
```bash
curl -X GET "https://vectispire.example.com/api/v1/attack-surface" \
  -H "Authorization: Bearer <VOTRE_JWT_TOKEN>"
```

### 4. Téléchargement du SBOM d'une Analyse
```bash
curl -X GET "https://vectispire.example.com/api/v1/scans/42/sbom" \
  -H "Authorization: Bearer <VOTRE_JWT_TOKEN>" \
  -o scan-42-sbom.json
```
