/**
 * Client-side paging of the target lists (repositories, images).
 *
 * <p>Twenty cards: a page a reader takes in without scrolling far, and few enough pages after a forge
 * import of a few hundred repositories that the paginator stays usable. A list that fits on one page
 * shows no paginator at all.
 */
export const PAGE_SIZE = 20;

/**
 * The first row of the page to show once the list has been replaced: the same page as before, unless
 * the list has shrunk under it — a target deleted elsewhere — in which case its new last page, never
 * an empty page past the end.
 */
export function pageHolding(first: number, length: number, size = PAGE_SIZE): number {
    if (first < length) return first;
    return Math.max(0, Math.floor((length - 1) / size) * size);
}
