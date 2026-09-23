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
        extends: [eslint.configs.recommended, ...tseslint.configs.recommended, ...angular.configs.tsRecommended],
        processor: angular.processInlineTemplates,
        rules: {
            // The prefixes the code actually carries, and the one `angular.json` declares for new
            // ones. The old file demanded `p`, which no selector here has ever used.
            '@angular-eslint/component-selector': ['error', { type: 'element', prefix: ['app', 'zs', 'vs'], style: 'kebab-case' }],
            '@angular-eslint/directive-selector': ['error', { type: 'attribute', prefix: ['app', 'zs', 'vs'], style: 'camelCase' }]
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
