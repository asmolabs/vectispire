import { Component, ChangeDetectionStrategy, inject } from '@angular/core';
import { RouterModule } from '@angular/router';
import { DialogFocusReturn } from './app/core/dialog-focus-return';

@Component({
    selector: 'zs-root',
    imports: [RouterModule],
    changeDetection: ChangeDetectionStrategy.Eager,
    template: `<router-outlet></router-outlet>`
})
export class AppComponent {
    constructor() {
        inject(DialogFocusReturn).start();
    }
}
