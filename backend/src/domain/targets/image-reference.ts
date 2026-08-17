/**
 * Validation of a container image reference.
 *
 * The same nature as `git-url.ts`: the reference is handed to a scanner that pulls it from a
 * registry. An uncontrolled value there pulls an arbitrary image — or, if it contains a
 * space, shifts the container command line's arguments.
 *
 * OCI's grammar is more permissive than what follows; anything that is not obviously an
 * image is refused here, at the price of turning away legitimate exotic forms. The cost of a
 * refusal is a message; the cost of one acceptance too many is not.
 */

const REGISTRY = /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:\d{1,5})?$/;
const IMAGE_NAME = /^[a-z0-9]+([._-][a-z0-9]+)*(\/[a-z0-9]+([._-][a-z0-9]+)*)*$/;
const TAG = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;

export interface ImageReference {
    registry: string | null;
    imageName: string;
    tag: string;
}

/** `null` if the reference is acceptable, otherwise the message to show. */
export function validateImageReference(reference: ImageReference): string | null {
    const { registry, imageName, tag } = reference;

    if (registry !== null && registry !== '' && !REGISTRY.test(registry)) {
        return `Invalid registry "${registry}". Expected a host, optionally followed by ":port".`;
    }
    if (!imageName) return 'The image name is required.';
    if (!IMAGE_NAME.test(imageName)) {
        // Upper case is refused by the registry itself, not by us: better to say so at
        // entry than at the first scan.
        return `Invalid image name "${imageName}". Lower case, digits, ". _ -" and "/".`;
    }
    if (!tag) return 'The tag is required ("latest" if nothing else).';
    if (!TAG.test(tag) && !DIGEST.test(tag)) {
        return `Invalid tag "${tag}". Expected a tag or a "sha256:…" digest.`;
    }
    return null;
}

/** The reference as a registry expects it — what is displayed and what is scanned. */
export function formatImageReference(reference: ImageReference): string {
    const base = reference.registry ? `${reference.registry}/${reference.imageName}` : reference.imageName;
    // A digest joins with "@", a tag with ":". Getting this wrong produces a reference the
    // registry rejects.
    return reference.tag.startsWith('sha256:') ? `${base}@${reference.tag}` : `${base}:${reference.tag}`;
}
