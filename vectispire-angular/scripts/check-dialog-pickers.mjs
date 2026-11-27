#!/usr/bin/env node
/**
 * Refuses a drop-down picker inside a dialog that does not open its list on the page's body.
 *
 * <p><b>Reported as "I cannot select a user's authorized projects".</b> Every project was among the
 * options; none could be ticked. An Optimus picker left as it is opens its list inside its own
 * element, and inside a `<p-dialog>` that element sits in the dialog's body, which scrolls
 * (`overflow: auto`) and is only as tall as its fields. The list was clipped to a strip drawn over
 * the hint below the field. No unit test of the options could see it — they were never missing —
 * and the teams dialog had the same two pickers in the same state, beside seven `p-select`s in other
 * dialogs. The dialogs that worked all said `appendTo="body"`, each one because somebody had
 * already been bitten.
 *
 * <p>A picker is `p-select`, `p-multiselect`, `p-datepicker`, `p-autocomplete`, `p-treeselect` or
 * `p-cascadeselect`; it is in a dialog when it sits between a `<p-dialog` and its closing tag, in
 * the same template. Any `appendTo` binding answers it — `appendTo="body"`, `[appendTo]="'body'"`
 * or a template variable — since the point is that the place was chosen.
 *
 * <p>Run by `npm test` before the unit suite, like the icon-button check.
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

/** Every template, inline ones included: a dialog can live in a component's `template:`. */
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
            return source.slice(start, i + 1);
        }
    }
    return source.slice(start);
}

/** Where each dialog's content starts and ends, nested dialogs accounted for. */
function dialogSpans(source) {
    const spans = [];
    const open = [];
    for (const match of source.matchAll(/<(\/?)p-dialog\b/g)) {
        if (match[1]) {
            const start = open.pop();
            if (start !== undefined) spans.push([start, match.index]);
        } else {
            open.push(match.index);
        }
    }
    // An unclosed dialog runs to the end of the template rather than escaping the check.
    for (const start of open) spans.push([start, source.length]);
    return spans;
}

const PICKER = /<(p-(?:select|multiselect|datepicker|autocomplete|treeselect|cascadeselect))\b/g;
const APPENDED = /\s\[?appendTo\]?\s*=/;

const offenders = [];
for (const { file, source } of templates()) {
    const withoutComments = source.replace(/<!--[\s\S]*?-->/g, (comment) => comment.replace(/[^\n]/g, ' '));
    const spans = dialogSpans(withoutComments);
    if (spans.length === 0) continue;
    for (const match of withoutComments.matchAll(PICKER)) {
        if (!spans.some(([start, end]) => start < match.index && match.index < end)) continue;
        if (APPENDED.test(openingTag(withoutComments, match.index))) continue;
        const line = withoutComments.slice(0, match.index).split('\n').length;
        offenders.push(`${relative(root, file)}:${line}  <${match[1]}> in a dialog opens its list inside it`);
    }
}

if (offenders.length > 0) {
    console.error(`${offenders.length} picker(s) in a dialog without appendTo:`);
    for (const offender of offenders) console.error(`  ${offender}`);
    console.error(
        'Add appendTo="body": inside the dialog the list is clipped by its scrolling body and cannot be used.'
    );
    process.exit(1);
}
console.log('Dialog picker check: every picker in a dialog opens its list on the body.');
