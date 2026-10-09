import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { Params, RouterLink } from '@angular/router';
import type { OwaspIssueLink } from '@/app/core/api.models';

/** Where a piece of the report's prose leads, or nothing for plain text. */
export interface SegmentRoute {
    commands: (string | number)[];
    queryParams?: Params;
}

export interface Segment {
    text: string;
    route: SegmentRoute | null;
}

/**
 * Splits model prose into text and links to the issues it names.
 *
 * **Only the identifiers the server sent become links, never anything that merely looks like one.**
 * The prose is model output derived from third-party content — advisories, scanner messages, the
 * audited repository's own files — and a pattern such as `CVE-\d+-\d+` would let that content decide
 * what the reader is invited to click. The server lists the identifiers the model was actually
 * shown, resolved against this repository's issues; anything else stays text, even when it reads
 * like a CVE. And the result is text and router commands, never markup: nothing here reaches
 * `innerHTML`.
 *
 * **Exact identifiers, longest first, never inside a longer token.** Identifiers hold `-`, `_`, `.`,
 * `:` and `/`, so a word boundary is not enough: `CVE-2026-1` must not link inside `CVE-2026-1000`
 * nor `CVE-2026-1-rc`. A match is refused when a letter, digit or `_` touches it, or when one of
 * those separators does with a letter or digit beyond it; a separator followed by a space or the
 * end — the full stop closing a sentence, a colon before a list — still lets it link.
 *
 * Compiled once per report: a report has hundreds of blocks and the identifiers do not change
 * between them.
 */
export function issueLinker(
    links: Record<string, OwaspIssueLink> | null | undefined,
    repositoryId: number | null
): (text: string | null | undefined) => Segment[] {
    const routes = new Map<string, SegmentRoute>();
    for (const [identifier, link] of Object.entries(links ?? {})) {
        const route = routeFor(identifier, link, repositoryId);
        if (identifier && route) routes.set(identifier, route);
    }
    if (routes.size === 0) {
        return (text) => (text ? [{ text, route: null }] : []);
    }

    const alternatives = [...routes.keys()].sort((a, b) => b.length - a.length).map(escape);
    const pattern = new RegExp(`(?<![\\w])(?<![\\w][-.:/])(?:${alternatives.join('|')})(?![\\w])(?![-.:/][\\w])`, 'g');

    return (text) => {
        if (!text) return [];
        const segments: Segment[] = [];
        let from = 0;
        for (const match of text.matchAll(pattern)) {
            if (match.index > from) segments.push({ text: text.slice(from, match.index), route: null });
            segments.push({ text: match[0], route: routes.get(match[0]) ?? null });
            from = match.index + match[0].length;
        }
        if (from < text.length) segments.push({ text: text.slice(from), route: null });
        return segments;
    };
}

function routeFor(identifier: string, link: OwaspIssueLink, repositoryId: number | null): SegmentRoute | null {
    if (link.issueId != null) {
        return { commands: ['/issues', link.issueId] };
    }
    // Several issues share the identifier — one CVE in three packages. The list is narrowed by a
    // search, which matches substrings: `CVE-2026-1` also finds `CVE-2026-1000`, so the list can be
    // a little longer than `count`. Accepted: it holds every issue meant, and a list one row long
    // is a better landing than a link to only one of the three.
    if (link.count > 1 && repositoryId !== null) {
        return { commands: ['/issues'], queryParams: { repository_id: repositoryId, search: identifier } };
    }
    return null;
}

function escape(identifier: string): string {
    return identifier.replace(/[.*+?^${}()|[\]\\/-]/g, '\\$&');
}

/** Segments in a row: text as text, a link as a router link. */
@Component({
    selector: 'zs-linked-text',
    imports: [RouterLink],
    changeDetection: ChangeDetectionStrategy.Eager,
    template: `@for (segment of segments(); track $index) {
        @if (segment.route; as route) {
            <a
                [routerLink]="route.commands"
                [queryParams]="route.queryParams"
                class="text-primary underline"
                data-testid="report-issue-link"
                >{{ segment.text }}</a
            >
        } @else {
            <span>{{ segment.text }}</span>
        }
    }`
})
export class LinkedText {
    readonly segments = input.required<Segment[]>();
}
