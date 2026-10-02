#!/usr/bin/env node
/**
 * Refuses a button that shows an icon and has no accessible name.
 *
 * <p><b>Why a script and not the template lint.</b> `@angular-eslint/template/elements-content`
 * reads native elements, and an Optimus `<p-button>` is a component to it: a trash icon with
 * neither a label nor an `ariaLabel` passed lint and reached a screen reader as "button", on a
 * row where the next button was another "button". And on a native `<button>` the rule is
 * satisfied by any child element — the `<i class="pi pi-…">` of an icon-only button is one — so an
 * icon alone counted as content. Both are what this file looks for.
 *
 * <p>A button is named when it has any of: `label`, `ariaLabel`, `aria-label`,
 * `aria-labelledby`, in any binding form (`[label]`, `[attr.aria-label]`…), or text of its own
 * between its tags — an interpolation included, since `{{ 'key' | translate }}` is text once
 * rendered. A `pTooltip` is not a name: it is shown on hover, and read by nothing.
 *
 * <p>A button with an icon is one carrying an `icon` attribute or containing a `pi pi-…` element.
 * Run by `npm test` before the unit suite, like the asset and i18n checks.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

function* walk(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = join(directory, entry.name);
        if (entry.isDirectory()) yield* walk(path);
        else yield path;
    }
}

/** Every template, the inline ones of the layout included: they are where the topbar lives. */
const templates = () =>
    [...walk(join(root, 'src/app'))].flatMap((file) => {
        if (file.endsWith('.html')) return [{ file, source: readFileSync(file, 'utf8') }];
        if (!file.endsWith('.ts') || file.endsWith('.spec.ts')) return [];
        const inline = readFileSync(file, 'utf8').match(/\btemplate:\s*`([\s\S]*?)`/);
        return inline ? [{ file, source: inline[1] }] : [];
    });

/**
 * The opening tag starting at `start`, read with its quotes respected: a binding such as
 * `[disabled]="count > 0"` holds a `>` that is not the end of the tag.
 */
function openingTag(source, start) {
    let quote = null;
    for (let i = start; i < source.length; i += 1) {
        const c = source[i];
        if (quote) {
            if (c === quote) quote = null;
        } else if (c === '"' || c === "'") {
            quote = c;
        } else if (c === '>') {
            return { text: source.slice(start, i + 1), end: i + 1 };
        }
    }
    return { text: source.slice(start), end: source.length };
}

/** The content up to the matching closing tag, nested elements of the same name accounted for. */
function contentOf(source, name, from) {
    const pattern = new RegExp(`<(/?)${name}\\b`, 'g');
    pattern.lastIndex = from;
    let depth = 1;
    for (let match = pattern.exec(source); match; match = pattern.exec(source)) {
        depth += match[1] ? -1 : 1;
        if (depth === 0) return source.slice(from, match.index);
    }
    return source.slice(from);
}

const NAMED_BY_ATTRIBUTE =
    /\s\[?(?:attr\.)?(?:label|ariaLabel|aria-label|aria-labelledby|ariaLabelledBy)\]?\s*=\s*(["'])(?!\1)/;
const HAS_ICON_ATTRIBUTE = /\s\[?icon\]?\s*=/;
const ICON_ELEMENT = /class\s*=\s*["'][^"']*\bpi\s+pi-/;

/** Text a reader would hear: tags and comments removed, an interpolation kept as text. */
function hasOwnText(content) {
    const text = content
        .replace(/<!--[\s\S]*?-->/g, '')
        .replace(/<[^>]*>/g, ' ')
        .replace(/@(?:if|else if|for|switch|case)\s*\([^)]*\)\s*\{|@else\s*\{|@default\s*\{|[{}](?!\{)/g, ' ');
    return /\{\{[\s\S]*?\}\}/.test(content) || /[A-Za-zÀ-ÿ0-9]/.test(text.replace(/\{\{[\s\S]*?\}\}/g, ''));
}

const offenders = [];
for (const { file, source } of templates()) {
    const withoutComments = source.replace(/<!--[\s\S]*?-->/g, (comment) => comment.replace(/[^\n]/g, ' '));
    for (const match of withoutComments.matchAll(/<(p-button|button|a)\b/g)) {
        const name = match[1];
        const tag = openingTag(withoutComments, match.index);
        // An anchor is a button here only when it is styled as one; a plain link's name is its text,
        // which the template lint already demands.
        if (name === 'a' && !/\spButton\b/.test(tag.text)) continue;
        const selfClosing = /\/>$/.test(tag.text);
        const content = selfClosing ? '' : contentOf(withoutComments, name, tag.end);

        const hasIcon = HAS_ICON_ATTRIBUTE.test(tag.text) || ICON_ELEMENT.test(content);
        if (!hasIcon) continue;
        if (NAMED_BY_ATTRIBUTE.test(tag.text) || hasOwnText(content)) continue;

        const line = withoutComments.slice(0, match.index).split('\n').length;
        offenders.push(`${relative(root, file)}:${line}  <${name}> shows an icon and has no accessible name`);
    }
}

if (offenders.length > 0) {
    console.error(`${offenders.length} icon button(s) without an accessible name:`);
    for (const offender of offenders) console.error(`  ${offender}`);
    console.error(
        `Give each a name a screen reader can say: [ariaLabel]="'…' | translate" on a <p-button>, ` +
            `[attr.aria-label] on a native <button>, with the key in both bundles.`
    );
    process.exit(1);
}
console.log('Icon button check: every button showing an icon has an accessible name.');
