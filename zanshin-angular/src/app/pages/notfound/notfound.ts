import { Component } from '@angular/core';
import { RouterModule } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { AppFloatingConfigurator } from '../../layout/component/app.floatingconfigurator';

import { CommonModule } from '@angular/common';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';

@Component({
    selector: 'app-notfound',
    standalone: true,
    imports: [CommonModule, RouterModule, AppFloatingConfigurator, ButtonModule, TranslatePipe],
    templateUrl: './notfound.html',
})
export class Notfound {}
