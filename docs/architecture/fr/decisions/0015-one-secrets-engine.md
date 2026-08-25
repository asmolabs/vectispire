# 0015 — Un seul moteur de secrets

**Date :** 2026-08-25 · **Statut :** accepté

## Contexte

L'étape secrets exécutait deux scanners : gitleaks, et un second emplacement nommé *betterleaks*.
L'audit du 25 août 2026 a établi ce qu'était réellement ce second emplacement.

`ScannerImages` aliasait `betterleaks` sur le digest épinglé de `gitleaks`, et
`BetterleaksScanner` lui passait le même `gitleaks.toml` avec les mêmes arguments. **Par défaut,
c'était le même moteur exécuté deux fois**, ne différant que par le nom du fichier de rapport — un
conteneur de plus par analyse pour exactement aucune couverture. Cela a été corrigé d'abord, en
sautant la seconde passe quand les deux images coïncident. Restait la question de savoir si la
couture devait exister.

Trois constats l'ont tranchée :

**La couture est plus étroite qu'elle n'en a l'air.** `BetterleaksScanner` codait en dur la ligne
de commande et le fichier de règles de gitleaks : la seule chose qu'elle pouvait accepter était une
image gitleaks-compatible — un fork, un miroir interne, une version épinglée plus ancienne. Un
moteur réellement différent — TruffleHog, detect-secrets, Nosey Parker — a besoin de ses propres
arguments et de ses propres règles, et n'y passerait pas.

**Ce cas étroit est déjà couvert.** Depuis que les images sont configurables, nommer
`vectispire.scanning.images.gitleaks` *remplace* le scanner de secrets. Qui veut un fork ou un
miroir fait cela, et obtient une passe au lieu de deux.

**Rien ne l'exerçait.** Aucun test n'a fait tourner le second moteur contre un vrai second moteur ;
les suites couvraient la décision de le sauter. Une couture avec une seule implémentation et
aucune couverture est maintenue par celui qui la lira ensuite, ce qui est la définition d'un coût
sans propriétaire.

## Décision

Un seul moteur de secrets. `BetterleaksScanner`, son emplacement d'image, ses entrées de
configuration et la fusion qui existait pour combiner deux jeux de résultats sont retirés.

## Conséquences

**Ceci suit la [0010](0010-one-scan-runner.md) plutôt que de s'en écarter.** Cette décision a
abandonné une interface `ScannerEngine` dont les trois implémentations s'étaient réduites à une,
au motif qu'une couture ne doit pas être reconstruite autour d'une implémentation unique. C'est la
même forme, et la garder aurait contredit une décision prise pour la même raison.

**Ce à quoi l'on renonce.** Faire tourner deux scanners de secrets simultanément et fusionner leurs
constats. Personne ne l'avait demandé, et la sémantique de fusion qu'il exigeait était une question
en soi : deux moteurs nommant le même secret sous des identifiants de règle différents produisent
deux anomalies, puisque `IssueFingerprint` inclut l'identifiant de règle. Cette question disparaît
avec la fonctionnalité.

**Ce qui reviendrait si on le voulait un jour.** Pas ceci. Un vrai second avis exige un gabarit
d'arguments par moteur et un fichier de règles par moteur — c'est un registre de scanners, donc une
décision, pas un emplacement. Il devrait rouvrir la [0010](0010-one-scan-runner.md) avec un
argument, plutôt que réapparaître sous forme d'un second nom d'image.

**Ce qui reste.** La signature qui a rendu le défaut d'origine impossible : le scanner retiré et
celui qui demeure renvoyaient tous deux des `List` nues, fusionnées dans une exception avalée — un
échec se lisait donc « analysé, rien trouvé » et *résolvait* des fuites d'identifiants.
`SecretsScanner` renvoie un `Optional`, `ScannerContractTest` vérifie que chaque scanner lançant un
conteneur en fait autant, et `ran(…)` ne compile contre rien d'autre.
