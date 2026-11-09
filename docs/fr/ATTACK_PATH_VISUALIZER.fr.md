# Vue des chemins d'attaque

La vue des chemins d'attaque (`AttackPathService`, `/api/v1/attack-paths`) met côte à côte, pour un
dépôt, les routes qu'il expose et les vulnérabilités critiques et secrets qu'il porte. **C'est une
heuristique de co-localisation, pas une analyse d'atteignabilité** : deux constats sont reliés parce
qu'ils appartiennent au même dépôt, jamais parce que quoi que ce soit a établi que l'un mène à
l'autre.

Lisez-la comme « ce dépôt a une route non authentifiée *et* une vulnérabilité critique — regardez-les
ensemble », non comme « cette vulnérabilité est exploitable depuis Internet ».

---

## Comment le graphe est construit

Pour chaque dépôt que l'appelant peut voir :

1. **Un nœud `Internet Ingress (0.0.0.0/0)`.** Synthétique : il est dessiné pour chaque dépôt, que
   l'application soit déployée ou non, et a fortiori joignable depuis Internet. Vectispire ne sait
   rien du réseau devant le code.
2. **Les routes exposées.** Chaque route de l'inventaire d'API déclarée publique ou qui n'exige aucune
   authentification (`authRequired = false`), reliée au nœud d'entrée. Une route non authentifiée
   dont le chemin contient `admin`, `auth`, `login`, `user`, `payment`, `checkout`, `secret`, `token`
   ou `upload` est dessinée critique, toute autre route non authentifiée élevée.
3. **Les composants vulnérables.** Les problèmes ouverts et non triés du dépôt qui sont critiques,
   élevés ou inscrits au catalogue CISA KEV (secrets à part), KEV d'abord puis par sévérité, dix au
   plus. **Chaque route exposée est reliée à chacun d'eux** — le produit des deux listes. L'arête ne
   signifie pas que la route appelle le composant : l'inventaire d'API n'enregistre aucun graphe
   d'appels, et Vectispire n'exécute aucune analyse de graphe d'appels (la colonne `reachability` du
   problème vaut `UNKNOWN` partout et le graphe ne la lit pas). Sans route exposée, les vulnérabilités
   sont reliées directement au nœud d'entrée.
4. **Un nœud `Database / Production Data Sink`**, fixe : dessiné pour chaque dépôt, relié depuis
   chaque vulnérabilité, que l'application ait une base de données ou non.
5. **Les secrets** trouvés dans le dépôt, dix au plus, reliés depuis la première vulnérabilité ou, à
   défaut, depuis le nœud d'entrée.

Un constat trié *non affecté*, *ne sera pas corrigé* ou *corrigé* est écarté. Les listes de nœuds sont coupées à dix pour
rester lisibles ; les comptes et le score ci-dessous sont calculés avant la coupe.

**« Exploitable » veut dire une seule chose ici :** un nœud de vulnérabilité est marqué exploitable
quand le dépôt a au moins une route non authentifiée — n'importe laquelle, pas une dont on aurait
montré qu'elle atteint ce composant.

## Scénarios et score

- **Route non authentifiée + vulnérabilité critique** : quand le dépôt a les deux, un scénario nomme
  sa première route non authentifiée et sa pire vulnérabilité, et aboutit au nœud de données.
- **Secret en clair** : quand le dépôt porte un secret, un scénario nomme le fichier.
- Sinon, un scénario de référence dit qu'aucun tel couple n'a été trouvé.

Le score de risque (0–100) vaut
`35 × scénarios + 25 × secrets + 10 × min(3, vulnérabilités) + 5 × min(3, routes non authentifiées)`,
au moins 15 dès qu'une vulnérabilité ou un secret est trouvé, et 10 sinon. Il classe les dépôts selon ce qu'ils
portent, pas selon une probabilité de compromission.

## Ce qu'elle ne peut pas dire

- si le code vulnérable est chargé ou appelé par une route ;
- si l'application est déployée, ni même joignable depuis Internet ;
- si une base de données, ou le système visé par le secret, est joignable depuis le composant
  vulnérable ;
- quoi que ce soit des conteneurs : la vue ne couvre que les dépôts.

Servez-vous-en pour décider quoi regarder ensemble, puis confirmez un chemin à la main avant de le
présenter comme tel.

## API REST

* `GET /api/v1/attack-paths/repositories/{repoId}` : le graphe et les scénarios d'un dépôt (404 pour
  un dépôt que l'appelant ne peut pas voir).
* `GET /api/v1/attack-paths/overview` : la même chose pour chaque dépôt que l'appelant peut voir.
