// @ts-check
//
// **This file used to exist without doing anything.** It exported an eslintrc object from a
// flat-config filename, which ESLint 9 rejects; none of the plugins it named were installed;
// `npm run lint` called `ng lint`, and `angular.json` has no lint target; no workflow ran it. Its
// selector rules demanded the prefix `p` while the code uses `app` and `zs`. Every rule below was
// therefore unenforced — the failure mode this project names most often: a check that exists on
// paper and verifies nothing.
//
// Now installed, run by `npm run lint`, and by CI. The rule sets are the maintained recommended
// ones rather than a hand-picked list; what is switched off is switched off with its reason.
const eslint = require('@eslint/js');
const tseslint = require('typescript-eslint');
const angular = require('angular-eslint');

module.exports = tseslint.config(
    {
        ignores: ['dist/**', 'out-tsc/**', '.angular/**', 'src/app/core/api.generated.ts']
    },
    {
        files: ['**/*.ts'],
        // **Type-aware**, because the defect it exists for is invisible without types. Fourteen
        // screens read `err.error.message` in an RxJS error callback — `any`, so every access
        // type-checked, and the server's RFC 7807 answer carries its sentence in `detail`: the
        // explanation never reached the screen. `no-unsafe-member-access` refuses the guess and
        // leaves `messageOf`, which knows the shape. `no-deprecated` is here because the build does
        // not say when Angular deprecates what we call.
        extends: [eslint.configs.recommended, ...tseslint.configs.recommendedTypeChecked, ...angular.configs.tsRecommended],
        languageOptions: { parserOptions: { projectService: true, tsconfigRootDir: __dirname } },
        processor: angular.processInlineTemplates,
        rules: {
            '@typescript-eslint/no-deprecated': 'error',
            // The prefixes the code actually carries, and the one `angular.json` declares for new
            // ones. The old file demanded `p`, which no selector here has ever used.
            '@angular-eslint/component-selector': ['error', { type: 'element', prefix: ['app', 'zs', 'vs'], style: 'kebab-case' }],
            '@angular-eslint/directive-selector': ['error', { type: 'attribute', prefix: ['app', 'zs', 'vs'], style: 'camelCase' }],
            // Angular 22 made OnPush the default, and its migration pinned every existing component
            // to `ChangeDetectionStrategy.Eager` so behaviour did not change underneath us: several
            // screens still keep state in plain fields assigned from callbacks, which OnPush would
            // stop rendering without an error. The rule reports exactly those 59 pins. Moving a screen
            // to OnPush means converting its state to signals and checking it in the browser — one
            // component at a time, not by silencing the pin. Switch this back on when none is left.
            '@angular-eslint/prefer-on-push-component-change-detection': 'off'
        }
    },
    {
        // Specs handle `any` by nature — `request.body`, `componentInstance` internals, JSON fixtures —
        // and switching these three on there reported 241 findings of which none was a defect: the
        // assertion that follows is the check. Everything else in the typed set still applies.
        files: ['**/*.spec.ts'],
        rules: {
            '@typescript-eslint/no-unsafe-member-access': 'off',
            '@typescript-eslint/no-unsafe-call': 'off',
            '@typescript-eslint/no-unsafe-assignment': 'off',
            // `expect(router.navigate).toHaveBeenCalled…` hands a spy to an assertion, never calls it.
            '@typescript-eslint/unbound-method': 'off'
        }
    },
    {
        files: ['**/*.html'],
        extends: [...angular.configs.templateRecommended, ...angular.configs.templateAccessibility],
        rules: {
            // `value != null` is the idiom for "neither null nor undefined", and the templates use
            // it on purpose; the old file allowed it too.
            '@angular-eslint/template/eqeqeq': ['error', { allowNullOrUndefined: true }],
            // `pButton` renders its `label` as the button's text, which the rule cannot see; an
            // icon-only button with neither a label nor an aria-label is still reported.
            '@angular-eslint/template/elements-content': ['error', { allowList: ['label', 'ariaLabel', 'aria-label'] }]
        }
    }
);
