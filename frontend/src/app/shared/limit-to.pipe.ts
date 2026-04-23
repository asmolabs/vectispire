import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'limitTo',
  standalone: true
})
export class LimitToPipe implements PipeTransform {
  transform(value: string | undefined | null, limit: number): string {
    if (!value) return '';
    return value.length > limit ? value.substring(0, limit) + '...' : value;
  }
}
