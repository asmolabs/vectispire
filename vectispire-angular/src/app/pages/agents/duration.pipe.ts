import { Pipe, PipeTransform } from '@angular/core';

/** `75` → `1m 15s`. The same in both languages, so pure: Angular calls it again only on a new value. */
export function formatDuration(seconds: number): string {
    if (!seconds || seconds <= 0) return '0s';
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    if (m > 0) {
        return `${m}m ${s}s`;
    }
    return `${s}s`;
}

@Pipe({ name: 'duration' })
export class DurationPipe implements PipeTransform {
    transform(seconds: number): string {
        return formatDuration(seconds);
    }
}
