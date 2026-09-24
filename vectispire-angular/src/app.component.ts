import { Component, ChangeDetectionStrategy } from '@angular/core';
import { RouterModule } from '@angular/router';

@Component({
    selector: 'zs-root',
    standalone: true,
    imports: [RouterModule],
    changeDetection: ChangeDetectionStrategy.Eager,
    template: `<router-outlet></router-outlet>`
})
export class AppComponent {}
