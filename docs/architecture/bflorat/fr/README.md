# Dossier d'Architecture Vectispire (Modèle Bertrand Florat — bflorat/modele-da)

Ce répertoire contient le **Dossier d'Architecture (DA)** de la plateforme **Vectispire** en version française, rédigé selon le modèle standardisé **[`bflorat/modele-da`](https://github.com/bflorat/modele-da)** (Bertrand Florat).

Ce modèle s'appuie sur une approche documentaire structurée en **5 Vues Métier et Techniques auto-porteuses** :

---

## 📑 Sommaire du Dossier d'Architecture (Français)

| N° | Vue d'Architecture | Document Markdown | Périmètre & Description |
|---|---|---|---|
| **01** | **Vue Applicative** | [`01_vue_applicative.md`](01_vue_applicative.md) | Composants applicatifs (Spring Boot / Angular), API REST, modèle de données, conciliation `Finding` vs `Issue`. |
| **02** | **Vue Sécurité** | [`02_vue_securite.md`](02_vue_securite.md) | Authentification Argon2id, RBAC, chiffrement AES-256-GCM, scellement d'audit SHA-256, isolation conteneurs & DFD STRIDE. |
| **03** | **Vue Dimensionnement & Perf.** | [`03_vue_dimensionnement.md`](03_vue_dimensionnement.md) | Exigences non fonctionnelles (ENF), volumétrie, baux de leadership, quotas mémoire JVM/Docker, purge de rétention. |
| **04** | **Vue Infrastructure & Déploiement** | [`04_vue_infrastructure.md`](04_vue_infrastructure.md) | SGBD multi-dialectes (PostgreSQL, MySQL, MariaDB, SQLite), migrations Flyway, socket Docker, agents distants. |
| **05** | **Vue Développement & Exploitation** | [`05_vue_developpement.md`](05_vue_developpement.md) | Stack JDK 25 / Node 24, contraintes ArchUnit, chaîne d'intégration CI/CD, SBOM Syft/Grype, procédures d'exploitation. |
