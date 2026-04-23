import { ChangeDetectorRef, Component, Host, HostBinding, Input, OnDestroy, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { NavigationEnd, Router, RouterModule } from '@angular/router';
import { Subscription, filter } from 'rxjs';
import { animate, state, style, transition, trigger } from '@angular/animations';
import { LayoutService } from '../service/layout.service';

@Component({
  // eslint-disable-next-line @angular-eslint/component-selector
  selector: '[app-menuitem]',
  standalone: true,
  imports: [CommonModule, RouterModule],
  template: `
    <ng-container>
      <div *ngIf="root && item.visible !== false" class="layout-menuitem-roottext">{{ item.label }}</div>
      <a
        *ngIf="(!item.routerLink || item.items) && item.visible !== false"
        [attr.href]="item.url"
        (click)="itemClick($event)"
        [ngClass]="item.class"
        [attr.target]="item.target"
        tabindex="0"
        pRipple
      >
        <i [ngClass]="item.icon" class="layout-menuitem-icon"></i>
        <span class="layout-menuitem-text">{{ item.label }}</span>
        <i class="pi pi-fw pi-angle-down layout-submenu-toggler" *ngIf="item.items"></i>
      </a>
      <a
        *ngIf="item.routerLink && !item.items && item.visible !== false"
        (click)="itemClick($event)"
        [ngClass]="item.class"
        [routerLink]="item.routerLink"
        routerLinkActive="active-route"
        [routerLinkActiveOptions]="item.routerLinkActiveOptions || { paths: 'exact', queryParams: 'ignored', matrixParams: 'ignored', fragment: 'ignored' }"
        [attr.target]="item.target"
        tabindex="0"
        pRipple
      >
        <i [ngClass]="item.icon" class="layout-menuitem-icon"></i>
        <span class="layout-menuitem-text">{{ item.label }}</span>
        <i class="pi pi-fw pi-angle-down layout-submenu-toggler" *ngIf="item.items"></i>
      </a>

      <ul *ngIf="item.items && item.visible !== false" [@children]="submenuAnimation">
        <ng-container *ngFor="let child of item.items; let i = index">
          <li app-menuitem [item]="child" [index]="i" [parentKey]="key" [root]="false"></li>
        </ng-container>
      </ul>
    </ng-container>
  `,
  animations: [
    trigger('children', [
      state('collapsed', style({ height: '0' })),
      state('expanded', style({ height: '*' })),
      transition('collapsed <=> expanded', animate('400ms cubic-bezier(0.86, 0, 0.07, 1)'))
    ])
  ]
})
export class AppMenuitem implements OnInit, OnDestroy {
  @Input() item: any;
  @Input() index!: number;
  @Input() @HostBinding('class.layout-root-menuitem') root!: boolean;
  @Input() parentKey!: string;

  active = false;
  menuSourceSubscription: Subscription;
  menuResetSubscription: Subscription;
  key: string = '';

  router = inject(Router);
  layoutService = inject(LayoutService);
  cd = inject(ChangeDetectorRef);

  constructor() {
    this.menuSourceSubscription = this.router.events
      .pipe(filter((event) => event instanceof NavigationEnd))
      .subscribe(() => {
        if (this.item.routerLink) {
          this.updateActiveStateFromRoute();
        }
      });

    this.menuResetSubscription = new Subscription(); // Placeholder for reset logic
  }

  ngOnInit() {
    this.key = this.parentKey ? this.parentKey + '-' + this.index : String(this.index);

    if (this.item.routerLink) {
      this.updateActiveStateFromRoute();
    }
  }

  updateActiveStateFromRoute() {
    let activeRoute = this.router.isActive(this.item.routerLink[0], { paths: 'exact', queryParams: 'ignored', matrixParams: 'ignored', fragment: 'ignored' });

    if (activeRoute) {
      // Logic for selecting the menu
    }
  }

  itemClick(event: Event) {
    if (this.item.disabled) {
      event.preventDefault();
      return;
    }

    if (this.item.routerLink || this.item.url) {
      // Toggle logic
    }

    if (this.item.items) {
      this.active = !this.active;
    }
  }

  get submenuAnimation() {
    return this.root ? 'expanded' : this.active ? 'expanded' : 'collapsed';
  }

  @HostBinding('class.active-menuitem')
  get activeClass() {
    return this.active;
  }

  ngOnDestroy() {
    if (this.menuSourceSubscription) {
      this.menuSourceSubscription.unsubscribe();
    }
    if (this.menuResetSubscription) {
      this.menuResetSubscription.unsubscribe();
    }
  }
}
