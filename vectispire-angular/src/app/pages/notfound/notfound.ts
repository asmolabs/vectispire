import { Component, ChangeDetectionStrategy } from '@angular/core';
import { RouterModule } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { AppFloatingConfigurator } from '../../layout/component/app.floatingconfigurator';

import { TranslatePipe } from '@/app/core/i18n/translate.pipe';

@Component({
    selector: 'app-notfound',
    imports: [RouterModule, AppFloatingConfigurator, ButtonModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './notfound.html'
})
export class Notfound {}
