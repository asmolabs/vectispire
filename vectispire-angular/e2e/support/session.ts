import { expect, type Page } from '@playwright/test';

/**
 * Signing in, including the password change the bootstrap account demands.
 *
 * **Why this exists.** A bootstrapped `SUPERUSER` is created with
 * `mustChangePassword` set, so the sign-in lands on `/change-password` and every guarded page
 * bounces back. Four of the five browser suites navigate straight to a guarded page, so every one
 * of them was looking at the sign-in screen and asserting whatever it could still see. Nobody
 * could know: the browser suite has never completed a run — the CI image was thirteen minor
 * versions behind Playwright and no browser launched at all.
 *
 * **Idempotent across runs on purpose.** The change is a one-way door and the SQLite file survives
 * a local re-run, so this tries the bootstrap password and falls back to the rotated one. A helper
 * that only worked on a fresh database would pass in CI and fail on the second local run, which is
 * the worst of both.
 */
export const BOOTSTRAP_PASSWORD = 'AdminVectispire2026!';

/** Rotated to on first use. Different from the bootstrap value, which the server refuses to reuse. */
export const E2E_PASSWORD = 'E2eVectispire2026!';

/**
 * Le mot de passe qui a marché, par compte, pour ne plus le redécouvrir.
 *
 * <p><b>Chaque essai raté est décompté par le serveur, et le budget est de cinq.</b>
 * {@code LoginThrottle} bloque un compte après cinq échecs dans une fenêtre de quinze minutes, et
 * ce sont des constantes de compilation. {@code VECTISPIRE_SECURITY_LOGIN_ATTEMPTS_PER_WINDOW},
 * que le nocturne pose à 200, relève le seau par adresse et non celui-ci.
 * Les helpers essayaient donc deux mots de passe à chaque connexion — un échec garanti par cas —
 * et une suite de dix-sept cas dépensait le budget de {@code admin} bien avant la fin. C'est
 * l'origine des « ni l'un ni l'autre mot de passe n'a été accepté » qui frappaient des cas sans
 * rapport les uns avec les autres.
 *
 * <p>Le cache vit dans le processus du worker : la première connexion cherche, les suivantes
 * savent.
 */
const known = new Map<string, string>();

async function signInWith(page: Page, username: string, ...candidates: string[]): Promise<boolean> {
    const remembered = known.get(username);
    if (remembered && (await attempt(page, remembered, username))) {
        return true;
    }

    for (const candidate of candidates) {
        if (candidate !== remembered && (await attempt(page, candidate, username))) {
            known.set(username, candidate);
            return true;
        }
    }
    return false;
}

export async function signIn(page: Page): Promise<void> {
    const accepted = await signInWith(page, 'admin', BOOTSTRAP_PASSWORD, E2E_PASSWORD);
    expect(accepted, 'neither the bootstrap nor the rotated password was accepted').toBe(true);

    if (!onChangePassword(page)) {
        return;
    }

    await rotate(page);

    // **Signed in again, because the change revokes every session the account had** — including
    // the one that just made it. Without this the helper returns on a page that is about to
    // redirect, and the case that follows fails against the sign-in screen for a reason that has
    // nothing to do with what it was testing.
    known.set('admin', E2E_PASSWORD);
    const afterRotation = await attempt(page, E2E_PASSWORD);
    expect(afterRotation, 'the rotated password was refused right after being set').toBe(true);
}

function onChangePassword(page: Page): boolean {
    return new URL(page.url()).pathname.startsWith('/change-password');
}

/** True when the credentials were accepted, whatever the screen we landed on. */
async function attempt(page: Page, password: string, username = 'admin'): Promise<boolean> {
    await page.goto('/login');
    await page.fill('#username', username);
    await page.fill('#password input', password);
    await page.click('button[type="submit"]');

    await page.waitForURL(/\/(dashboard|change-password|issues|overview|targets)/, { timeout: 15_000 }).catch(() => {});
    return !new URL(page.url()).pathname.startsWith('/login');
}

async function rotate(page: Page): Promise<void> {
    await page.fill('#current input', BOOTSTRAP_PASSWORD);
    await page.fill('#next input', E2E_PASSWORD);
    await page.fill('#confirm input', E2E_PASSWORD);
    await page.click('button[type="submit"]');

    // Left the screen, so the change was accepted. Asserted rather than assumed: a refusal here
    // leaves the form in place, and every case after it would fail on something unrelated.
    await expect(page).not.toHaveURL(/\/change-password/, { timeout: 15_000 });
}

/**
 * Navigates inside the running application, rather than reloading it.
 *
 * <p><b>`page.goto` signs you out, and that is the product working as designed.</b> The session
 * token lives in memory and deliberately not in `localStorage`, so that an injected script cannot
 * read it — the store says so in its own comment. A full navigation drops it, and the guard sends
 * the browser back to the sign-in screen.
 *
 * <p>Every browser case in this repository used `page.goto` after signing in, so every one of them
 * was asserting against the sign-in screen. Four of them asserted only that a `body` was visible,
 * which is true there, so nothing ever said so.
 */
export async function goTo(page: Page, path: string): Promise<void> {
    await page.getByRole('link', { name: LINKS[path] ?? path, exact: false }).first().click();
    await expect(page).toHaveURL(new RegExp(`${path.replace('/', '\\/')}(\\?|$)`), { timeout: 15_000 });
}

/**
 * Le bouton qui propose un triage, quel que soit le libellé qu'il porte.
 *
 * <p><b>Écrit ici parce qu'il l'était quatre fois.</b> Le libellé dépend du rôle — « Triage »
 * quand la décision clôt, « Send for approval » quand elle part en file — et il vient de le
 * dépendre aussi de la langue, en passant par le dictionnaire. Les quatre copies étaient en
 * français en dur ; trois suites sont donc devenues aveugles d'un coup, et une assertion
 * « aucun bouton de triage » qui ne trouve rien parce qu'elle cherche le mauvais mot ne dit
 * plus rien du tout.
 */
export const TRIAGE_BUTTON = /^(Triage|Send for approval)( \(\d+\))?$/;

/** Le bouton qui valide la boîte de triage, dont le libellé suit la même règle. */
export const TRIAGE_SAVE = /save|enregistrer|approval|approbation/i;

/** The sidebar wording for the paths the suites visit. */
const LINKS: Record<string, string> = {
    '/issues': 'Issues',
    '/licenses': 'Open Source Licenses',
    '/settings': 'Settings',
    '/audit-log': 'Audit log',
    '/attestation': 'Attestation',
    '/remediation': 'Remediation',

    // **Les six écrans de preuve, atteints par la barre latérale comme les autres.** C'est
    // délibérément le chemin d'un lecteur : une page dont la route répond mais dont aucune entrée
    // de menu ne parle est une page que personne n'ouvrira, et un `page.goto` direct ne peut pas
    // voir la différence.
    '/exceptions': 'Exceptions register',
    '/gate-verdicts': 'Verdict register',
    '/remediation-delays': 'Time to fix',
    '/soa': 'Statement of applicability',
    '/certified-scope': 'Certified scope',

    // Le bandeau de couverture n'a pas d'écran à lui : il se pose sur ceux où son absence produit
    // une conclusion fausse. Celui-ci est le seul des deux qui ait une entrée de menu.
    '/rule-sets': 'Semgrep rules'
};

/** Le mot de passe des comptes de rôle, et celui vers lequel le premier usage le fait tourner. */
export const ROLE_PASSWORD = 'RoleVectispire2026!';
export const ROLE_PASSWORD_ROTATED = 'RoleVectispire2026Bis!';

/**
 * Se connecte avec un compte du rôle demandé, en le créant au besoin.
 *
 * <p><b>Pourquoi ce détour, plutôt que le compte d'amorçage.</b> L'amorçage crée un
 * {@code SUPERUSER}, et ce rôle gouverne la plateforme sans y agir : il ne trie pas, n'ouvre pas de
 * ticket, ne lance pas de revue. Les suites qui trient signaient donc avec le seul compte qui n'en
 * a pas le droit — elles passaient parce qu'elles simulent l'API de triage, ce qui est une autre
 * façon de ne pas le savoir. Le détour reproduit ce qu'une installation réelle fait : le compte
 * racine crée les comptes de travail.
 *
 * <p><b>Le jeton est passé à la main, et il le faut.</b> `page.request` partage les cookies du
 * navigateur, or la session de Vectispire vit en mémoire et non dans un cookie — un choix
 * délibéré de `SessionStore`. Sans en-tête explicite, l'appel de création part sans identifiant
 * et le serveur a raison de le refuser.
 *
 * <p><b>Et le compte créé doit changer son mot de passe</b>, comme celui de l'amorçage. La
 * rotation est tentée une fois puis les deux mots de passe sont essayés, pour qu'une réexécution
 * locale sur la même base se comporte comme la première.
 */
export async function signInAs(page: Page, role: 'ADMIN' | 'CISO' | 'AUDITOR' | 'USER'): Promise<string> {
    const username = `e2e-${role.toLowerCase()}`;

    // **Le chemin court d'abord.** Le compte survit d'une exécution à l'autre : passé la
    // première, tout ce détour se résume à une connexion. Le faire quand même coûtait cinq
    // navigations par cas — la connexion d'amorçage, sa rotation, la création, puis la connexion
    // du compte — et faisait dépasser le délai des suites qui appellent ceci dans un `beforeEach`.
    if (known.has(username) && (await attempt(page, known.get(username)!, username))) {
        return username;
    }
    if (!known.has(username) && (await attempt(page, ROLE_PASSWORD_ROTATED, username))) {
        known.set(username, ROLE_PASSWORD_ROTATED);
        return username;
    }

    await signIn(page);
    const token = await tokenFor(page, 'admin', E2E_PASSWORD, BOOTSTRAP_PASSWORD);
    // **Le refus n'est pas asserté, et la connexion qui suit l'est.** Le compte peut déjà
    // exister — une réexécution locale sur la même base, ou un autre cas du même fichier qui l'a
    // créé avant. Ce qui compte n'est pas que cet appel réussisse mais qu'un compte de ce rôle
    // existe et puisse se connecter, et c'est l'assertion d'après qui le dit.
    await page.request.post('/api/v1/users', {
        headers: { Authorization: `Bearer ${token}` },
        data: { username, password: ROLE_PASSWORD, role, display_name: username }
    });

    const accepted = await signInWith(page, username, ROLE_PASSWORD, ROLE_PASSWORD_ROTATED);
    expect(accepted, `ni l'un ni l'autre mot de passe n'a été accepté pour ${username}`).toBe(true);

    if (new URL(page.url()).pathname.startsWith('/change-password')) {
        await page.fill('#current input', ROLE_PASSWORD);
        await page.fill('#next input', ROLE_PASSWORD_ROTATED);
        await page.fill('#confirm input', ROLE_PASSWORD_ROTATED);
        await page.click('button[type="submit"]');
        await expect(page).not.toHaveURL(/\/change-password/, { timeout: 15_000 });

        // Le changement révoque toutes les sessions du compte, celle qui vient de le faire
        // comprise — même raison que pour l'amorçage.
        known.set(username, ROLE_PASSWORD_ROTATED);
        const again = await attempt(page, ROLE_PASSWORD_ROTATED, username);
        expect(again, `le mot de passe tourné a été refusé juste après avoir été posé`).toBe(true);
    }

    return username;
}

/** Un jeton porteur, obtenu par l'API : c'est la seule façon d'authentifier `page.request`. */
async function tokenFor(page: Page, username: string, ...passwords: string[]): Promise<string> {
    // **Les codes sont retenus pour l'échec.** « Aucun mot de passe n'a produit de jeton » ne
    // distingue pas un mot de passe faux d'un 429 du limiteur de tentatives ou d'un 502 du proxy
    // pendant que le serveur de développement recompile — trois causes qui se corrigent
    // autrement, et dont deux n'ont rien à voir avec le test.
    const refusals: number[] = [];
    for (const password of passwords) {
        const response = await page.request.post('/api/v1/auth/login', { data: { username, password } });
        if (response.ok()) {
            const token = (await response.json())['token'];
            if (token) return token;
        }
        refusals.push(response.status());
    }
    throw new Error(
        `aucun mot de passe n'a produit de jeton pour ${username} (réponses : ${refusals.join(', ')})`);
}
