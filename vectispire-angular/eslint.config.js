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

const FLUSHED_LITERAL =
    'A flushed literal is checked against nothing: wrap it in asSchema/asSchemaList with the schema the route answers, or write it `satisfies AnswerOf<…>` for a route the document types as a bare map.';

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
        // **Specs are typed like the code they test.** The three `no-unsafe-*` rules used to be off
        // here, on the ground that specs handle `any` by nature — `request.body`, `nativeElement` —
        // and that the assertion which follows is the check. It is not: `body.expires_in_days` kept
        // compiling whatever `TriageRequest` became, and `{ … } as never` opened sessions for a user
        // with an `id` the server does not send and without the `mfaEnabled` it does. A body is read
        // as the type the client method takes, the page as an `HTMLElement`, a fixture as its model.
        //
        // `as never` and `as unknown as` are the same hole spelt as a cast, so they are refused too.
        // A value the client's union does not hold yet goes through `newerServerWord`
        // (core/testing/contract.ts), which keeps the rest of the fixture checked. What must stay is
        // allowed by a disable comment that says why (`-- reason`); scripts/check-spec-types.mjs
        // refuses one without a reason and holds their number to a ratchet.
        files: ['**/*.spec.ts'],
        // Not the Playwright specs. The `no-unsafe-*` rules reach them anyway, as errors from the
        // recommended set above — the full set found three bodies they had left untyped. What this
        // block adds there is the two cast bans, and the suite's two `as unknown as` (the
        // `openapi.json` literal, Angular's debug `window.ng`) would each need an exception;
        // scripts/check-spec-types.mjs reads `src/` only, so the two stay consistent.
        ignores: ['e2e/**'],
        rules: {
            '@typescript-eslint/no-explicit-any': 'error',
            '@typescript-eslint/no-unsafe-member-access': 'error',
            '@typescript-eslint/no-unsafe-call': 'error',
            '@typescript-eslint/no-unsafe-assignment': 'error',
            '@typescript-eslint/no-unsafe-argument': 'error',
            '@typescript-eslint/no-unsafe-return': 'error',
            'no-restricted-syntax': [
                'error',
                {
                    selector: 'TSAsExpression > TSNeverKeyword.typeAnnotation',
                    message:
                        '`as never` fits anything and checks nothing: build the value with its real type, or use newerServerWord for a word the client does not know.'
                },
                {
                    selector: 'TSAsExpression > TSAsExpression.expression > TSUnknownKeyword.typeAnnotation',
                    message:
                        '`as unknown as` silences the whole value: type the fixture, or use newerServerWord for the one field the client does not know.'
                },
                // **A flushed literal is the server's answer, written by hand and checked by nothing.**
                // `flush` takes `any`, so `{ enabled: false }` answered a status the client reads three
                // fields of, `{}` a declaration, `{ key: null }` an issued key: 175 of them until
                // 2026-10-15, fifty-six describing an answer the server cannot send. A success body
                // goes through `asSchema`/`asSchemaList` (core/testing/contract.ts), or `satisfies
                // AnswerOf<…>` for a route the document types as a bare map. An error body — a second
                // argument whose status is 400 or more, or named — is a problem document and stays as it is.
                {
                    selector:
                        "CallExpression[callee.property.name='flush'][arguments.length=1][arguments.0.type='ObjectExpression']",
                    message: FLUSHED_LITERAL
                },
                {
                    selector:
                        "CallExpression[callee.property.name='flush'][arguments.0.type='ObjectExpression'][arguments.1.type='ObjectExpression']:has(Property[key.name='status'] > Literal[value<400])",
                    message: FLUSHED_LITERAL
                },
                {
                    selector:
                        "CallExpression[callee.property.name='flush'][arguments.0.type='ArrayExpression']:matches([arguments.0.elements.0.type='ObjectExpression'], [arguments.0.elements.1.type='ObjectExpression'])",
                    message: FLUSHED_LITERAL
                },
                {
                    selector:
                        "CallExpression[callee.property.name='flush'] > ConditionalExpression > :matches(ObjectExpression, ArrayExpression[elements.0.type='ObjectExpression'])",
                    message: FLUSHED_LITERAL
                }
            ],
            // `expect(router.navigate).toHaveBeenCalled…` hands a spy to an assertion, never calls it.
            '@typescript-eslint/unbound-method': 'off'
        }
    },
    {
        // **The Playwright suite, linted since 2026-10-15.** `npm run lint` used to say `eslint src`,
        // so these files were never read; and the nearest tsconfig, the root one, gives no Node types
        // under TypeScript 6, so `process`, `Buffer` and the whole `mysql2` connection were `any` —
        // the unsafe rules could only have reported noise. `tsconfig.e2e.json` types them.
        files: ['e2e/**/*.ts', 'playwright.config.ts'],
        languageOptions: {
            parserOptions: { projectService: false, project: './tsconfig.e2e.json', tsconfigRootDir: __dirname }
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
            // icon-only button with neither a label nor an aria-label is still reported. An Optimus
            // `<p-button>`, or an `<i>` icon alone inside a `<button>`, is not: scripts/check-icon-buttons.mjs.
            '@angular-eslint/template/elements-content': ['error', { allowList: ['label', 'ariaLabel', 'aria-label'] }]
        }
    }
);
