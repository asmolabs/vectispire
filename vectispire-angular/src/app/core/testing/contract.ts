import document from '../../../../openapi.json';
import type { components } from '../api.generated';

type Schemas = components['schemas'];

/**
 * Checks a test fixture against the schema it claims to be, from the control plane's own document.
 *
 * <h2>The hole this closes</h2>
 *
 * <p><b>A fixture is a belief about the server that nothing confronts with the server.</b> Three
 * layers already stand between a screen and the API: {@code ClientContractSpecTest} pins the
 * document to the routes, {@code Refine} pins the client's types to the document, and Angular's
 * template checker pins a screen to its types. All three check <em>types</em>. A fixture is a
 * literal, written by hand, and a literal that is wrong is simply a different test passing.
 *
 * <p>That is not hypothetical here. The scan detail screen read `detail.id` where the server
 * nests the summary under `scan`, and ten fields of its header rendered blank — while the smoke
 * fixture spread the summary flat, so the test agreed with the screen and both were wrong. The
 * gate policy fixtures went on passing after a field was added to the request, because they
 * described a policy the server had stopped sending. Neither was caught by a type.
 *
 * <h2>What it checks, and why it stops there</h2>
 *
 * <ul>
 *   <li><b>Every property the fixture carries exists in the schema.</b> This is the one that
 *       catches a shape flattened, a field renamed, or a key invented — the failures above.
 *   <li><b>Every property the document marks required is present.</b> Which is the primitives:
 *       springdoc marks nothing else, and the client's own claims live in `api.models.ts`.
 *   <li><b>Scalars hold the declared type.</b> A number where a string is documented is a
 *       fixture that would have to be wrong on the wire too.
 * </ul>
 *
 * <p><b>`null` is accepted everywhere, and that is not laxity.</b> The document marks nothing
 * nullable while this server sends `displayName: null`, so refusing null here would reject
 * fixtures that are exactly right. Nullability is claimed in `api.models.ts`, per field, where
 * a person can be held to it.
 *
 * <p>Unknown schema names fail rather than pass: a fixture pointing at a schema the document does
 * not have is a fixture nobody can check, and silently accepting it would be the failure this
 * whole file is about.
 */
export function asSchema<K extends keyof Schemas>(name: K, fixture: unknown): Schemas[K] {
    const problems = check(name as string, fixture, name as string);
    if (problems.length > 0) {
        throw new Error(
            `The fixture does not match the schema "${String(name)}" the control plane publishes:\n` +
                problems.map((problem) => `  · ${problem}`).join('\n') +
                '\n\nIf the change is intended, regenerate the contract:\n' +
                "  ./gradlew :vectispire-core:test --tests '*ClientContractSpecTest*' " +
                '-Dvectispire.openapi.write=true'
        );
    }
    return fixture as Schemas[K];
}

/** The same, for a route that answers with a list. */
export function asSchemaList<K extends keyof Schemas>(name: K, fixtures: unknown[]): Schemas[K][] {
    return fixtures.map((fixture) => asSchema(name, fixture));
}

interface JsonSchema {
    $ref?: string;
    type?: string;
    format?: string;
    required?: string[];
    properties?: Record<string, JsonSchema>;
    items?: JsonSchema;
    additionalProperties?: JsonSchema | boolean;
    enum?: unknown[];
}

const SCHEMAS = (document as { components: { schemas: Record<string, JsonSchema> } }).components
    .schemas;

function check(schemaName: string, value: unknown, path: string): string[] {
    const schema = SCHEMAS[schemaName];
    if (!schema) {
        return [`${path}: the document has no schema called "${schemaName}"`];
    }
    return against(schema, value, path);
}

function against(schema: JsonSchema, value: unknown, path: string): string[] {
    if (schema.$ref) {
        return check(schema.$ref.split('/').pop() as string, value, path);
    }
    // The server sends nulls the document cannot describe; see the note above.
    if (value === null || value === undefined) {
        return [];
    }

    switch (schema.type) {
        case 'array':
            if (!Array.isArray(value)) {
                return [`${path}: the document says array, the fixture holds ${typeOf(value)}`];
            }
            return schema.items
                ? value.flatMap((item, index) => against(schema.items as JsonSchema, item, `${path}[${index}]`))
                : [];
        case 'object':
        case undefined:
            return object(schema, value, path);
        case 'string':
        case 'integer':
        case 'number':
        case 'boolean':
            return scalar(schema, value, path);
        default:
            return [];
    }
}

function object(schema: JsonSchema, value: unknown, path: string): string[] {
    if (typeof value !== 'object' || Array.isArray(value)) {
        return [`${path}: the document says object, the fixture holds ${typeOf(value)}`];
    }
    const holder = value as Record<string, unknown>;
    const problems: string[] = [];

    // A free-form map — `backlogBySeverity` and its kind. Its keys are data, not a shape.
    if (!schema.properties && schema.additionalProperties) {
        const values =
            typeof schema.additionalProperties === 'object' ? schema.additionalProperties : null;
        if (values) {
            Object.entries(holder).forEach(([key, entry]) =>
                problems.push(...against(values, entry, `${path}.${key}`))
            );
        }
        return problems;
    }

    const declared = schema.properties ?? {};
    for (const key of Object.keys(holder)) {
        if (!(key in declared)) {
            problems.push(
                `${path}.${key}: the fixture carries this, the document does not declare it` +
                    (Object.keys(declared).length > 0
                        ? ` (it declares ${Object.keys(declared).sort().join(', ')})`
                        : '')
            );
        }
    }
    for (const key of schema.required ?? []) {
        if (holder[key] === undefined) {
            problems.push(`${path}.${key}: the document marks this always sent, the fixture omits it`);
        }
    }
    for (const [key, entry] of Object.entries(holder)) {
        const declaration = declared[key];
        if (declaration) {
            problems.push(...against(declaration, entry, `${path}.${key}`));
        }
    }
    return problems;
}

function scalar(schema: JsonSchema, value: unknown, path: string): string[] {
    const actual = typeOf(value);
    const expected = schema.type === 'integer' ? 'number' : schema.type;
    if (actual !== expected) {
        return [`${path}: the document says ${schema.type}, the fixture holds ${actual}`];
    }
    if (schema.enum && !schema.enum.includes(value)) {
        return [
            `${path}: the document allows ${schema.enum.map((one) => JSON.stringify(one)).join(', ')},` +
                ` the fixture holds ${JSON.stringify(value)}`
        ];
    }
    return [];
}

function typeOf(value: unknown): string {
    if (value === null) {
        return 'null';
    }
    return Array.isArray(value) ? 'array' : typeof value;
}
