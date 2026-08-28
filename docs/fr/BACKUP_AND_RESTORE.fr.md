# Sauvegarde et restauration

*English version: [`docs/en/BACKUP_AND_RESTORE.md`](../en/BACKUP_AND_RESTORE.md).*

Une procédure de sauvegarde que personne n'a exécutée est une croyance. Cette page est la
procédure ; [`scripts/restore-drill.sh`](../../scripts/restore-drill.sh) en est la preuve, et il
tourne toutes les nuits.

## 1. Les trois états, dont un seul saute aux yeux

| | Où il vit | Ce qu'on perd avec lui |
|---|---|---|
| **La base** | `vectispire_mysql_data` | Cibles, constats, décisions de triage, utilisateurs, clés d'API, la table d'audit |
| **Le miroir d'audit** | `vectispire_audit` | La copie indépendante du journal d'audit — voir §5 |
| **`ENCRYPTION_KEY`** | **Dans aucun des deux** | La capacité de lire tout ce que la base garde scellé |

La troisième ligne est celle qui tue des entreprises. La clé vient de l'environnement ou de
`ENCRYPTION_KEY_FILE` ; elle n'est délibérément dans aucun volume, si bien qu'une sauvegarde
parfaite des deux volumes, restaurée sans elle, donne un plan de contrôle qui **démarre, répond, et
ne peut lire aucune clé de déploiement, aucun identifiant de registre, aucun jeton de ticketing**.
Rien dans cette restauration ne ressemble à un échec jusqu'à ce que quelqu'un lance une analyse.

## 2. Sauvegarder

**La base — un dump, pas une copie de volume.** Copier `/var/lib/mysql` sous un moteur en marche
capture une page à moitié écrite aussi volontiers qu'une page entière.

```bash
docker exec vectispire-db mysqldump -u vectispire -p"$MYSQL_PASSWORD" \
  --single-transaction --routines --triggers vectispire > vectispire-$(date +%F).sql
```

`--single-transaction` est ce qui rend le dump cohérent sans verrouiller les tables dans
lesquelles le plan de contrôle écrit.

**Le miroir d'audit — séparément, et là où le plan de contrôle ne peut pas écrire.** C'est un
fichier NDJSON en ajout seul. Une copie simple suffit :

```bash
docker run --rm -v vectispire_audit:/audit:ro -v "$PWD:/out" alpine \
  cp /audit/audit.ndjson /out/audit-$(date +%F).ndjson
```

*Séparément* n'est pas une formalité. Toute la valeur du miroir tient à ce qu'il n'est pas la
table. Une sauvegarde qui capture les deux au même instant et les restaure ensemble produit deux
copies qui concordent **parce qu'elles ont été restaurées ensemble**, non parce que rien n'a été
altéré. Le §5 est tout l'argument.

**La clé — pas ici.** `ENCRYPTION_KEY` a sa place dans ce qui garde vos autres secrets, avec une
traçabilité de détention. Si elle est dans la même archive que la base, l'archive est une base en
clair avec des étapes en plus. Voir [`KEY_ROTATION.fr.md`](KEY_ROTATION.fr.md).

## 3. Restaurer

Dans un moteur **vide** — charger un dump par-dessus un schéma existant fusionne deux états et en
produit un troisième qui n'a jamais existé.

```bash
docker compose down
docker volume rm vectispire_mysql_data
docker compose up -d db          # recrée le volume, vide
# attendre qu'il accepte les connexions, puis :
docker exec -i vectispire-db mysql -u vectispire -p"$MYSQL_PASSWORD" vectispire < vectispire-2026-08-27.sql
docker compose up -d
```

Ne restaurez **pas** `vectispire_audit` en même temps. Laissez le miroir vivant en place. §5.

## 4. La clé, et le mode de défaillance que le tirage ne couvre pas

Le tirage nocturne prouve que le dump se restaure et que la chaîne d'audit survit. Il ne prouve pas
que la restauration est *lisible*, parce que cela dépend d'une valeur qui n'est pas dans la
sauvegarde.

Avant de considérer une restauration comme terminée, avec quelqu'un qui regarde :

1. Se connecter et ouvrir une cible à laquelle une clé de déploiement est attachée.
2. Lancer une analyse dessus.

Une analyse qui s'authentifie est la seule preuve que la clé sous laquelle vous avez restauré est
celle sous laquelle les données ont été écrites. **Un plan de contrôle avec la mauvaise clé est
sain sur tous les tableaux de bord.** Si l'analyse échoue à s'authentifier et que la clé est
perdue, les colonnes scellées le sont avec elle — restaurez la clé depuis sa détention, ou
ressaisissez chaque identifiant à la main. Il n'y a pas de troisième option, et c'est la propriété
qui fonctionne : c'est ce qui fait qu'une base volée ne vaut rien.

## 5. Lire la vérification après une restauration

`GET /api/v1/audit-log/verify` — à l'écran, la bannière de vérification de la page *Journal
d'audit*.

Après avoir restauré une base plus ancienne en gardant le miroir vivant, le résultat honnête n'est
**pas** « intact » :

```json
{"total":5,"intact":false,"broken":null,"mirrored":true,"missingFromTable":5,"missingFromMirror":0}
```

À lire ainsi : la chaîne tient (`broken: null` — aucune ligne n'a été altérée), et le miroir détient
cinq entrées que la table restaurée n'a pas. **Ce nombre est le reçu de la restauration.** C'est le
nombre d'actions auditées survenues entre le dump et la restauration, et il devrait correspondre à
peu près au temps écoulé. S'il est bien plus grand, votre dump est plus vieux que vous ne le
croyiez.

La même restauration, maintenant, avec le miroir restauré à côté — ce que fait un « on restaure
tout » naïf :

```json
{"total":7,"intact":true,"broken":null,"mirrored":true,"missingFromTable":0,"missingFromMirror":5}
```

**`intact: true`, par-dessus cinq entrées d'audit qui n'existent plus nulle part.** La perte n'a pas
diminué ; c'est son unique témoin qui a été écrasé. Ce n'est pas un défaut de la vérification —
`intact` vaut `broken == null && missingFromTable == 0` délibérément, parce que `missingFromMirror`
a des explications innocentes (lignes antérieures au miroir, miroir injoignable) et qu'une alarme
d'intégrité qui crie au loup est une alarme que plus personne ne lit. Mais cela signifie une chose
pour un opérateur :

> **Après une restauration, `intact` n'est pas le contrôle. Lisez aussi `missingFromMirror`.** Une
> valeur non nulle dans les heures qui suivent une restauration signifie que vous avez restauré le
> miroir aussi, et que vous n'avez plus de trace indépendante de ce que la base a perdu.

Les deux relevés ci-dessus sont imprimés par le tirage à chaque exécution. Ce ne sont pas des
illustrations.

## 6. Le tirage

```bash
scripts/restore-drill.sh
```

Il ne construit rien de ce qui vous appartient et ne touche aucun déploiement : chaque conteneur,
réseau et volume qu'il crée porte le préfixe `drill-`, et il refuse de démarrer autrement. Il monte
un plan de contrôle, prend un dump, effectue des actions auditées *après* le dump, restaure dans un
moteur neuf, et vérifie ce que décrit le §5 — y compris le cas aveugle, qui doit rapporter
`intact: true`. Si cette assertion venait à échouer, le danger a changé de forme et cette page
décrit autre chose.

Il tourne dans [`nightly.yml`](../../.github/workflows/nightly.yml). Une procédure de restauration
vérifiée une fois est une procédure vérifiée sur le code de ce jour-là.
