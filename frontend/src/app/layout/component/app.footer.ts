import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LayoutService } from '../service/layout.service';

@Component({
  selector: 'app-footer',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="layout-footer">
      <span class="font-medium ml-2">Zanshin - Git Security Scanner</span>
    </div>
  `
})


export class AppFooter {
  layoutService = inject(LayoutService);
}
