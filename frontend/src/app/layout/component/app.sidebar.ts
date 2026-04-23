import { Component, ElementRef, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AppMenu } from './app.menu';

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [CommonModule, AppMenu],
  template: `
    <div class="layout-sidebar">
      <app-menu></app-menu>
    </div>
  `
})
export class AppSidebar {
  constructor(public el: ElementRef) {}
}
