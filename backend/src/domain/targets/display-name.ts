/**
 * The name a target is displayed under — **one single definition**.
 *
 * The Repositories screen shortened the URL client-side while the dashboard showed the whole
 * URL: the same repository carried two names depending on the page, and nothing told the
 * user they were the same. The name therefore belongs to the server, which returns it
 * identically to all its callers.
 */

/** `org/project` from a git URL, whatever its form. */
export function shortRepositoryName(url: string): string {
    const withoutSuffix = url.replace(/\.git$/, '').replace(/\/+$/, '');
    const segments = withoutSuffix.split(/[/:]/).filter(Boolean);
    // The last two segments: `org/project`, including on an SCP form
    // (`git@host:team/subgroup/project`) where the first ":" is not a port.
    return segments.slice(-2).join('/') || withoutSuffix;
}

/** The name the operator chose if they gave one, otherwise the short form. */
export function repositoryDisplayName(repository: { name: string | null; url: string }): string {
    return repository.name?.trim() || shortRepositoryName(repository.url);
}

export function containerDisplayName(container: { imageName: string; tag: string }): string {
    // The digest is not shortened here: this name also serves as a search key and an export
    // label, where the whole value matters. Shortening is a display concern.
    return `${container.imageName}:${container.tag}`;
}
