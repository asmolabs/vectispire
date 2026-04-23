import { Component, OnDestroy, Renderer2, ViewChild, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { NavigationEnd, Router, RouterModule } from '@angular/router';
import { Subscription, filter } from 'rxjs';
import { AppSidebar } from './app.sidebar';
import { AppTopbar } from './app.topbar';
import { AppFooter } from './app.footer';
import { LayoutService } from '../service/layout.service';

@Component({
  selector: 'app-layout',
  standalone: true,
  imports: [CommonModule, RouterModule, AppSidebar, AppTopbar, AppFooter],
  template: `
    <div class="layout-wrapper" [ngClass]="containerClass">
      <app-topbar></app-topbar>
      <app-sidebar></app-sidebar>
      <div class="layout-main-container">
        <div class="layout-main">
          <router-outlet></router-outlet>
        </div>
        <app-footer></app-footer>
      </div>
      <div class="layout-mask"></div>
    </div>
  `
})
export class AppLayout implements OnDestroy {
  layoutService = inject(LayoutService);
  renderer = inject(Renderer2);
  router = inject(Router);

  overlayMenuOpenSubscription: Subscription;
  menuOutsideClickListener: any;
  profileMenuOutsideClickListener: any;

  @ViewChild(AppSidebar) appSidebar!: AppSidebar;
  @ViewChild(AppTopbar) appTopbar!: AppTopbar;

  constructor() {
    this.overlayMenuOpenSubscription = this.router.events
      .pipe(filter((event) => event instanceof NavigationEnd))
      .subscribe(() => {
        this.hideMenu();
      });
  }

  hideMenu() {
    this.layoutService.state.update((prev) => ({
      ...prev,
      overlayMenuActive: false,
      staticMenuMobileActive: false,
      menuHoverActive: false
    }));
    if (this.menuOutsideClickListener) {
      this.menuOutsideClickListener();
      this.menuOutsideClickListener = null;
    }
    this.unblockBodyScroll();
  }

  unblockBodyScroll(): void {
    if (document.body.classList) {
      document.body.classList.remove('blocked-scroll');
    } else {
      document.body.className = document.body.className.replace(new RegExp('(^|\\b)' + 'blocked-scroll'.split(' ').join('|') + '(\\b|$)', 'gi'), ' ');
    }
  }

  get containerClass() {
    const layoutConfig = this.layoutService.config();
    const layoutState = this.layoutService.state();
    return {
      'layout-theme-light': !layoutConfig.darkTheme,
      'layout-theme-dark': layoutConfig.darkTheme,
      'layout-overlay': layoutConfig.menuMode === 'overlay',
      'layout-static': layoutConfig.menuMode === 'static',
      'layout-static-inactive': layoutState.staticMenuDesktopInactive && layoutConfig.menuMode === 'static',
      'layout-overlay-active': layoutState.overlayMenuActive,
      'layout-mobile-active': layoutState.staticMenuMobileActive,
      'layout-input-filled': false,
      'layout-reveal': false,
      'p-ripple-disabled': false
    };
  }

  ngOnDestroy() {
    if (this.overlayMenuOpenSubscription) {
      this.overlayMenuOpenSubscription.unsubscribe();
    }

    if (this.menuOutsideClickListener) {
      this.menuOutsideClickListener();
    }
  }
}
