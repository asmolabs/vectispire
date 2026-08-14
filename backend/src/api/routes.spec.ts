import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Toute méthode publique d'un contrôleur porte un décorateur de route.
 *
 * **Ce test existe parce qu'une route a disparu sans que rien ne le dise.** Un
 * remplacement automatisé a écrasé `@Get()` en insérant des annotations OpenAPI
 * au-dessus ; TypeScript a compilé sans broncher — une méthode sans décorateur est
 * simplement une méthode inatteignable — et les 562 tests sont restés verts, parce
 * qu'aucun ne traverse la couche HTTP pour cet écran.
 *
 * Le symptôme aurait été un 404 sur le backlog, découvert par un utilisateur. Une méthode
 * publique dans un contrôleur qui n'est pas une route est presque toujours une erreur, et
 * c'est bon marché à vérifier.
 */

const CONTROLLERS = join(__dirname);
const ROUTE_DECORATORS = /@(Get|Post|Put|Patch|Delete|All|Head|Options)\s*\(/;

/** Ce qui n'est légitimement pas une route : le constructeur et les aides privées. */
const NOT_A_ROUTE = /^(constructor|private|protected|static|get |set )/;

/**
 * Les mots-clés qui ressemblent à une déclaration de méthode.
 *
 * `if (`, `for (`, `catch (` s'indentent aussi à quatre espaces au premier niveau d'un
 * corps de méthode. Sans cette liste, le test signale une trentaine de fausses alertes et
 * devient exactement le genre de barrière qu'on désactive au bout d'une semaine.
 */
const KEYWORDS = new Set(['if', 'for', 'while', 'switch', 'catch', 'return', 'await', 'do', 'else']);

function controllerFiles(): string[] {
    return readdirSync(CONTROLLERS).filter((name) => name.endsWith('.controller.ts'));
}

describe('routes des contrôleurs', () => {
    it('trouve les contrôleurs (sinon ce test ne prouverait rien)', () => {
        expect(controllerFiles().length).toBeGreaterThan(10);
    });

    it.each(controllerFiles())('%s — chaque méthode publique est une route', (file) => {
        const lines = readFileSync(join(CONTROLLERS, file), 'utf8').split('\n');
        const orphans: string[] = [];

        for (let index = 0; index < lines.length; index += 1) {
            const line = lines[index];
            // Une méthode de classe : quatre espaces d'indentation, un nom, une parenthèse.
            const method = /^ {4}(?:async )?([a-zA-Z][a-zA-Z0-9]*)\s*\(/.exec(line);
            if (!method) continue;
            if (NOT_A_ROUTE.test(line.trim())) continue;
            if (KEYWORDS.has(method[1])) continue;

            // Les décorateurs précèdent la méthode : on remonte tant qu'on lit des
            // annotations, des continuations d'annotation ou des commentaires.
            let hasRoute = false;
            for (let above = index - 1; above >= 0; above -= 1) {
                const previous = lines[above].trim();
                if (previous === '' || previous.startsWith('*') || previous.startsWith('/*') || previous.startsWith('//')) continue;
                if (ROUTE_DECORATORS.test(previous)) {
                    hasRoute = true;
                    break;
                }
                // Toute autre annotation, ou une ligne de continuation, ne tranche pas.
                if (previous.startsWith('@') || previous.startsWith(')') || previous.startsWith('}') || previous.endsWith(',') || previous.endsWith('+')) continue;
                break;
            }

            if (!hasRoute) orphans.push(`${method[1]} (ligne ${index + 1})`);
        }

        expect(orphans).toEqual([]);
    });
});
