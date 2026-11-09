# 0020 — Les captures restent en PNG, et le déclencheur qui changera cela est nommé

**Date :** 2026-09-21 · **Statut :** accepté · **Décideur :** Laurent Boucher

## Contexte

`docs-site` porte 42 captures d'écran générées — 21 écrans en deux langues, 1280×860, PNG
truecolour 8 bits, **5,5 Mo**. Elles sont produites par `screens.spec.ts` plutôt que prises à la
main, pour la raison que donne l'en-tête de ce fichier : une image est couplée au pixel, et
`mkdocs --strict` sait voir un lien mort mais jamais la photographie d'une colonne supprimée il y
a trois mois.

C'est le fait qu'elles soient générées qui rend la question de la taille digne d'être posée. Une
capture prise à la main est remplacée quand quelqu'un s'aperçoit qu'elle est périmée ; une capture
générée est **réécrite par chaque campagne**, et git conserve chaque version pour toujours. Deux
campagnes ont eu lieu dans la semaine du 14 septembre 2026, et la seconde a touché dix-sept images
pour une raison qui n'était pas une refonte — le masque de chargement était capturé en plein
fondu. Le dépôt grossit donc de près des 5,5 Mo entiers à chaque balayage d'une campagne, et non
de la taille de ce qui a réellement changé à l'écran.

Quatre options ont été mesurées plutôt qu'estimées, sur les 42 fichiers :

| option | total | fidélité |
|---|---|---|
| tel que commité | 5584 k | — |
| ré-encodage PNG (Pillow `optimize`, `compress_level=9`) | 5730 k | identique — **plus gros** |
| PNG en palette de 256 couleurs | ~2100 k | **dégradé** |
| WebP sans perte (`cwebp -z 9`) | **1999 k** | identique, vérifié |

Trois résultats ont tranché :

**L'encodeur PNG de Playwright est déjà à l'optimum pour ce contenu.** Le ré-encoder perd 3 %. Il
n'y a aucun gain sans perte gratuit à récupérer dans le format actuel, ce qui écarte l'option qui
n'aurait rien coûté à prendre.

**La quantification est dominée.** Les captures ne portent que 1500 à 5800 couleurs distinctes,
donc une palette de 256 entrées coupe bien 62 % — mais elle dépense l'antialiasing de chaque
glyphe pour atteindre le chiffre que le WebP sans perte atteint sans rien dépenser. Une option
moins bonne sur les deux axes qu'une autre option disponible n'appelle pas d'argument
supplémentaire.

**Le WebP sans perte coupe 64 %, et l'affirmation a été vérifiée plutôt que crue.** `cwebp
-lossless` suivi de `dwebp` rend une image identique au pixel ; l'aller-retour a été exécuté sur
trois captures et `ImageChops.difference` n'a trouvé de boîte englobante sur aucune.

## Décision

**Les captures restent en PNG. La conversion en WebP sans perte est différée, et la condition qui
la déclenche est écrite ici plutôt que laissée à celui qui remarquera le prochain que le
répertoire est gros.**

**Convertir quand un troisième axe apparaîtra** — une troisième langue, ou une seconde résolution.
Les deux multiplient le nombre de fichiers au lieu de s'y ajouter, et 64 % d'un nombre qu'on vient
de multiplier valent les coûts ci-dessous. 64 % de 5,5 Mo, non.

Les coûts, et c'est pourquoi le déclencheur est une multiplication et non un seuil :

- `page.screenshot()` n'émet que du png ou du jpeg. Le WebP réclame une étape de conversion après
  la capture, donc **l'artefact commité cesse d'être exactement ce que le navigateur a produit** —
  une propriété autour de laquelle cette suite est par ailleurs construite.
- `libwebp` devient une dépendance du job e2e et de quiconque régénère en local.
- Les 42 références d'image dans le markdown changent, dans les deux langues.
- **Un changement de version de `cwebp` réécrirait les 42 fichiers d'un coup.** C'est la même
  classe de bruit que le correctif de masque, et le même genre de diff que personne ne peut lire.
  Si ce chantier est repris, `cwebp` est épinglé par empreinte comme `ScannerImages` épingle Syft
  et Grype — pour la raison qui y est donnée : l'outil qui produit un artefact commité fait partie
  de l'artefact.

## Ce que cette décision ne fait pas, dit plutôt que sous-entendu

**Elle ne prétend pas que 5,5 Mo soient un problème aujourd'hui.** Ils ne le sont pas.
L'argumentation porte sur la pente, pas sur la valeur, et la décision à laquelle elle aboutit est
de ne rien faire — ce qui est précisément pourquoi le déclencheur doit être écrit. Un report sans
condition nommée est indiscernable d'un oubli, et rouvre comme une enquête neuve chaque fois que
quelqu'un lance `du`.

**Elle ne couvre pas les autres images du site.** Les diagrammes C4 sont du SVG généré, et du
texte ; rien de ce qui précède ne s'y applique.

**Elle n'autorise pas les captures prises à la main.** Rien ne change dans la façon dont les
captures sont produites, seulement dans les octets où elles sont rangées.

## Conséquences

La prochaine campagne commite du PNG, comme toutes les précédentes. Rien ne change dans
`screens.spec.ts`.

Un lecteur qui trouve `docs-site/assets/screens` volumineux dispose de cet enregistrement au lieu
de l'enquête qui l'a produit : les chiffres sont ici, l'aller-retour a été exécuté, et la seule
question qui reste est de savoir si le déclencheur s'est déclenché.

Quand il se déclenchera, le travail sera une étape de conversion dans `shoot()`, un `cwebp`
épinglé, un balayage des références markdown, et un unique commit qui change 42 fichiers pour une
raison que le message de commit tient en une ligne.
