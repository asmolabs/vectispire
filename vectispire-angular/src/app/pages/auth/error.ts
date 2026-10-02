import { Component, ChangeDetectionStrategy } from '@angular/core';
import { RouterModule } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { RippleModule } from '@openng/optimus-ui/ripple';
import { AppFloatingConfigurator } from '../../layout/component/app.floatingconfigurator';

import { TranslatePipe } from '@/app/core/i18n/translate.pipe';

@Component({
    selector: 'app-error',
    imports: [ButtonModule, RippleModule, RouterModule, AppFloatingConfigurator, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './error.html'
})
export class Error {}
