# Règles Semgrep de Zanshin

Ces règles sont écrites ici, pour ce projet, et n'ont pas d'autre licence que la sienne.

## Pourquoi pas les règles publiques de Semgrep

Semgrep a changé la licence de `semgrep/semgrep-rules` : la *Semgrep Rules License v1.0*
dit explicitement qu'elle **n'autorise pas à distribuer les règles**. Les embarquer ici
serait une redistribution, quelle que soit l'intention.

Le fork pris avant ce changement, `opengrep/opengrep-rules`, est redistribuable
(LGPL-2.1 + Commons Clause) — mais la Commons Clause interdirait à tout reprenant de
Zanshin de vendre un service dont la valeur dérive substantiellement de ces règles, et
ferait sortir ce dépôt de l'open source au sens de l'OSI. C'est cher payé pour des règles
écrites par quelqu'un d'autre.

D'où le partage : Zanshin embarque ses propres règles, et
[`scripts/fetch_semgrep_rules.py`](../../../../../scripts/fetch_semgrep_rules.py) installe
celles que vous choisissez, **sur votre machine**, directement depuis leur auteur. Le
répertoire obtenu se déclare dans `ZANSHIN_SEMGREP_RULES_DIR`, et les deux jeux sont
fusionnés au moment du scan.

Le scan reste hors ligne : la récupération se fait une fois, à l'installation, pas à
chaque analyse.

## Ce que couvre le jeu embarqué

| Langage | Sécurité | Qualité |
|---|---|---|
| Python | injection de commande, `eval`, désérialisation, TLS non vérifié, PRNG faible, comparaison à temps non constant, Jinja sans échappement, Flask en debug | `except` nu, exception avalée, argument par défaut mutable, `open` hors contexte, comparaison à un singleton, `assert` en production |
| JavaScript / TypeScript | `eval`, `child_process.exec`, `innerHTML`, redirection ouverte, TLS non vérifié, empreinte faible, `jwt.decode` sans vérification, `Math.random` pour un secret | `catch` vide, `==`, `console.log` oublié, `debugger`, `await` dans une boucle |
| Java | commande concaténée, SQL concaténé, empreinte et chiffrement faibles, PRNG faible, XXE, confiance TLS aveugle | `catch` vide, `printStackTrace`, `System.out`, concaténation en boucle |

Kotlin n'est pas couvert : sa syntaxe diffère assez pour qu'un motif Java ne s'y applique
pas, et écrire correctement cette moitié est un travail à part — dit ici pour que personne
ne suppose une couverture qui n'existe pas.

## Écrire une règle

Le fichier décide de la nature du constat, et le test le vérifie :
`security.yaml` doit porter `metadata.category: security` (constats de type `sast`, traités
comme des vulnérabilités), `quality.yaml` tout le reste (`correctness`, `best-practice`,
`performance`, `maintainability` — constats de type `quality`, qui ne peuvent jamais faire
échouer un gate CI).

Trois exigences, chacune vérifiée par `tests/test_semgrep_rules_backends.py` :

1. **Toute règle doit se déclencher** sur un cas de
   [`tests/semgrep_fixtures/`](../../../../../tests/semgrep_fixtures). Un jeu de règles qui
   ne trouve rien ressemble exactement à du code propre.
2. **Tout cas voisin doit rester muet.** Chaque déclenchement attendu est marqué
   `zanshin: <id>` dans la fixture ; les lignes non marquées ne doivent rien produire.
   C'est cette moitié qui rend le jeu utilisable : un scanner qui crie au loup est un
   scanner qu'on désactive.
3. **`metadata.category`, `confidence` et une sévérité** parmi `ERROR`/`WARNING`/`INFO`.
   `confidence: LOW` fait descendre la sévérité d'un cran, ce qui place le constat sous le
   seuil de gate par défaut : visible, mais incapable de casser une compilation.

Les identifiants de règle entrent dans l'empreinte d'un problème. **Renommer une règle
efface son historique de triage** : le problème est résolu et un nouveau apparaît.
