import { Pipe, PipeTransform } from '@angular/core';

export type TagSeverity = 'info' | 'success' | 'warn' | 'danger' | 'secondary';

/** A route's method as a tag's tone: the more it changes, the warmer. */
export function methodSeverity(method: string | null | undefined): TagSeverity {
    switch (method?.toUpperCase()) {
        case 'GET':
            return 'info';
        case 'POST':
            return 'success';
        case 'PUT':
        case 'PATCH':
            return 'warn';
        case 'DELETE':
            return 'danger';
        default:
            return 'secondary';
    }
}

/** A route's documentation state as a tag's tone: a route no contract declares is the alarm. */
export function shadowSeverity(status: string | null | undefined): Exclude<TagSeverity, 'info'> {
    switch (status) {
        case 'DOCUMENTED':
            return 'success';
        case 'SHADOW_API':
            return 'danger';
        case 'UNDOCUMENTED':
            return 'warn';
        case 'HIGH_RISK_EXPOSURE':
            return 'danger';
        default:
            return 'secondary';
    }
}

/**
 * Pure, the tone depending on the value alone: the rows of a paginated table are template contexts a
 * computed cannot reach without re-mapping every endpoint, and the pipe is called again only on a new value.
 */
@Pipe({ name: 'methodSeverity' })
export class MethodSeverityPipe implements PipeTransform {
    transform(method: string | null | undefined): TagSeverity {
        return methodSeverity(method);
    }
}

@Pipe({ name: 'shadowSeverity' })
export class ShadowSeverityPipe implements PipeTransform {
    transform(status: string | null | undefined): Exclude<TagSeverity, 'info'> {
        return shadowSeverity(status);
    }
}
