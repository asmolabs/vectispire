import { Component } from '@angular/core';
import { RouterModule } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { RippleModule } from '@openng/optimus-ui/ripple';
import { AppFloatingConfigurator } from '../../layout/component/app.floatingconfigurator';

import { CommonModule } from '@angular/common';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';

@Component({
    selector: 'app-access',
    standalone: true,
    imports: [CommonModule, ButtonModule, RouterModule, RippleModule, AppFloatingConfigurator, TranslatePipe],
    templateUrl: './access.html',
})
export class Access {}
