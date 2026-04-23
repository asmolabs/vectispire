import { Component, inject, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService, Repository, Scan } from '../api';
import { SocketService } from '../socket.service';
import { AuthService } from '../auth/auth.service';
import { AddRepoComponent } from '../add-repo/add-repo';
import { RepoListComponent } from '../repo-list/repo-list';
import { Subscription } from 'rxjs';
import { TableModule } from 'primeng/table';
import { ButtonModule } from 'primeng/button';
import { DialogModule } from 'primeng/dialog';
import { TabsModule } from 'primeng/tabs';
import { CardModule } from 'primeng/card';
import { TagModule } from 'primeng/tag';
import { ScanDetailsComponent } from '../scan-details/scan-details';
import { LimitToPipe } from '../shared/limit-to.pipe';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [
    CommonModule, 
    AddRepoComponent, 
    RepoListComponent, 
    LimitToPipe,
    TableModule,
    ButtonModule,
    DialogModule,
    TabsModule,
    CardModule,
    TagModule,
    ScanDetailsComponent
  ],
  template: `
    <div class="grid p-fluid">
      <div class="col-12" *ngIf="canManage()">
        <app-add-repo (repoAdded)="fetchRepos()"></app-add-repo>
      </div>

      <div class="col-12" *ngIf="criticalProjects.length > 0">
        <div class="card shadow-1 border-round p-4 surface-card border-left-3 border-red-500 mb-4" style="background: rgba(254, 242, 242, 0.5)">
          <div class="flex align-items-center gap-2 mb-3">
            <i class="pi pi-exclamation-triangle text-red-600 text-2xl"></i>
            <h5 class="m-0 font-bold text-red-900 uppercase tracking-wider">Security Alerts: Critical Vulnerabilities Detected</h5>
          </div>
          <div class="grid">
            <div *ngFor="let item of criticalProjects" class="col-12 md:col-6 lg:col-4">
              <div class="flex align-items-center justify-content-between p-3 border-round bg-white shadow-1 border-1 border-red-100 hover:shadow-2 transition-all transition-duration-200">
                <div class="flex flex-column gap-1 overflow-hidden">
                  <span class="font-bold text-900 white-space-nowrap overflow-hidden text-overflow-ellipsis">{{item.repo.name || (item.repo.url | limitTo: 20)}}</span>
                  <div class="flex align-items-center gap-2">
                    <p-tag [value]="item.criticalCount + ' CRITICAL'" severity="danger" [rounded]="true" styleClass="text-xs font-bold"></p-tag>
                    <span class="text-xs text-500">{{item.repo.branch}}</span>
                  </div>
                </div>
                <p-button icon="pi pi-arrow-right" [text]="true" size="small" (click)="selectScan({repo: item.repo, scan: item.scan})" pTooltip="View Scan Details"></p-button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="col-12 md:col-6">
        <div class="card shadow-1 border-round p-4 surface-card mb-4 min-h-20rem">
          <h5 class="m-0 font-semibold mb-3">Total Projects</h5>
          <div class="flex flex-column align-items-center justify-content-center h-full pt-4">
            <svg width="200" height="200" viewBox="0 0 200 200" class="project-svg">
              <defs>
                <linearGradient id="grad1" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" style="stop-color:#6366f1;stop-opacity:1" />
                  <stop offset="100%" style="stop-color:#a855f7;stop-opacity:1" />
                </linearGradient>
                <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur in="SourceAlpha" stdDeviation="3" />
                  <feOffset dx="0" dy="2" result="offsetblur" />
                  <feComponentTransfer>
                    <feFuncA type="linear" slope="0.3" />
                  </feComponentTransfer>
                  <feMerge>
                    <feMergeNode />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>
              <circle cx="100" cy="100" r="80" fill="none" stroke="#f1f5f9" stroke-width="12" />
              <circle cx="100" cy="100" r="80" fill="none" stroke="url(#grad1)" stroke-width="12" 
                      stroke-linecap="round" [attr.stroke-dasharray]="projectCircleDash" 
                      style="transition: stroke-dasharray 0.8s ease-out; transform: rotate(-90deg); transform-origin: 50% 50%;" />
              <text x="100" y="95" text-anchor="middle" font-size="44" font-weight="bold" fill="#1e293b" class="font-sans">
                {{repositories.length}}
              </text>
              <text x="100" y="125" text-anchor="middle" font-size="14" fill="#64748b" font-weight="500">
                PROJETS
              </text>
            </svg>
          </div>
        </div>
      </div>

      <div class="col-12 md:col-6">
        <div class="card shadow-1 border-round p-4 surface-card mb-4 min-h-20rem">
          <h5 class="m-0 font-semibold mb-3">Total Vulnerabilities</h5>
          <div class="flex flex-column md:flex-row align-items-center justify-content-center h-full pt-2">
            <svg width="200" height="200" viewBox="0 0 100 100" class="donut-svg mr-4">
              <circle cx="50" cy="50" r="40" fill="none" stroke="#f1f5f9" stroke-width="10" />
              <ng-container *ngFor="let segment of donutSegments">
                <circle cx="50" cy="50" r="40" fill="none" 
                        [attr.stroke]="segment.color" 
                        stroke-width="10" 
                        [attr.stroke-dasharray]="segment.dashArray" 
                        [attr.stroke-dashoffset]="segment.dashOffset"
                        style="transition: all 0.5s ease-out; transform: rotate(-90deg); transform-origin: 50% 50%;" />
              </ng-container>
              <text x="50" y="47" text-anchor="middle" font-size="16" font-weight="bold" fill="#1e293b">
                {{totalVulnerabilities}}
              </text>
              <text x="50" y="60" text-anchor="middle" font-size="6" fill="#64748b" font-weight="600">
                TOTAL
              </text>
            </svg>
            <div class="flex flex-column gap-2 mt-4 md:mt-0">
               <div *ngFor="let item of vulnerabilityLegend" class="flex align-items-center gap-2">
                  <span [style.background-color]="item.color" class="block border-round" style="width: 12px; height: 12px"></span>
                  <span class="text-sm font-medium text-700">{{item.label}}:</span>
                  <span class="text-sm font-bold text-900">{{item.value}}</span>
               </div>
            </div>
          </div>
        </div>
      </div>

      <div class="col-12">
        <div class="card shadow-1 border-round p-4 surface-card">
          <div class="flex justify-content-between align-items-center mb-4">
            <h5 class="m-0 font-semibold">Repositories & Branch Scans</h5>
            <div class="flex align-items-center gap-3">
               <p class="text-secondary m-0 flex align-items-center gap-2 text-sm">
                <span class="status-dot" [class.online]="isOnline"></span>
                {{ isOnline ? 'Real-time updates enabled' : 'Connecting...' }}
              </p>
              <p-button label="Refresh" icon="pi pi-refresh" [outlined]="true" size="small" (click)="fetchRepos()"></p-button>
            </div>
          </div>
          
          <app-repo-list 
            [repositories]="repositories"
            (viewDetails)="selectScan($event)"
            (rescan)="onRescan($event)">
          </app-repo-list>
        </div>
      </div>

      <app-scan-details 
        [(display)]="displayDetails" 
        [repo]="selectedRepo" 
        [scan]="selectedScan"
        (displayChange)="!$event && closeModal()">
      </app-scan-details>
    </div>
  `,
  styles: [`
    .status-dot { width: 10px; height: 10px; border-radius: 50%; background: #ef4444; display: inline-block; }
    .status-dot.online { background: #10b981; box-shadow: 0 0 8px #10b981; }
    pre { white-space: pre-wrap; word-break: break-all; }
  `]
})
export class AppDashboard implements OnInit, OnDestroy {
  private api = inject(ApiService);
  private socket = inject(SocketService);
  private auth = inject(AuthService);
  
  repositories: Repository[] = [];
  selectedRepo: Repository | null = null;
  selectedScan: Scan | null = null;
  displayDetails = false;
  isOnline = false;
  criticalProjects: {repo: Repository, scan: Scan, criticalCount: number}[] = [];

  canManage(): boolean {
    const user = this.auth.user();
    return user?.role === 'admin' || user?.role === 'superuser';
  }

  donutSegments: any[] = [];
  vulnerabilityLegend: any[] = [];
  totalVulnerabilities = 0;
  projectCircleDash = "0 502"; // 2 * PI * 80 ~= 502

  private subs = new Subscription();

  ngOnInit() {
    this.fetchRepos();
    this.subs.add(this.socket.onScanUpdated().subscribe(() => this.fetchRepos()));
    this.subs.add(this.socket.onConnect().subscribe(() => this.isOnline = true));
    this.subs.add(this.socket.onDisconnect().subscribe(() => this.isOnline = false));
  }

  ngOnDestroy() {
    this.subs.unsubscribe();
  }

  onRescan(event: {repoId: number, branch: string, subPath?: string}) {
    this.api.triggerRescan(event.repoId, event.branch, event.subPath).subscribe();
  }

  fetchRepos() {
    this.api.getRepositories().subscribe(repos => {
      this.repositories = repos;
      this.updateCharts();
      if (this.selectedScan) {
        const repo = repos.find(r => r.id === this.selectedRepo?.id);
        if (repo) {
          const updatedScan = repo.scans.find(s => s.id === this.selectedScan?.id);
          if (updatedScan) this.selectedScan = updatedScan;
        }
      }
    });
  }

  updateCharts() {
    let critical = 0, high = 0, medium = 0, low = 0;
    
    this.repositories.forEach(repo => {
      if (repo.scans && repo.scans.length > 0) {
        const latestScan = repo.scans.find(s => s.status === 'completed');
        if (latestScan && latestScan.summary) {
          critical += latestScan.summary.critical || 0;
          high += latestScan.summary.high || 0;
          medium += latestScan.summary.medium || 0;
          low += latestScan.summary.low || 0;
        }
      }
    });

    this.totalVulnerabilities = critical + high + medium + low;
    this.vulnerabilityLegend = [
      { label: 'Critical', value: critical, color: '#dc2626' },
      { label: 'High', value: high, color: '#ea580c' },
      { label: 'Medium', value: medium, color: '#ca8a04' },
      { label: 'Low', value: low, color: '#38bdf8' }
    ];

    // Donut logic
    const r = 40;
    const circumference = 2 * Math.PI * r;
    let currentOffset = 0;
    
    this.donutSegments = this.vulnerabilityLegend
      .filter(item => item.value > 0)
      .map(item => {
        const percentage = (item.value / this.totalVulnerabilities);
        const dashArray = `${percentage * circumference} ${circumference}`;
        const dashOffset = -currentOffset;
        currentOffset += percentage * circumference;
        return { ...item, dashArray, dashOffset };
      });

    // Project circle logic
    const projectR = 80;
    const projectCircumference = 2 * Math.PI * projectR;
    this.projectCircleDash = `${projectCircumference} ${projectCircumference}`;

    // Critical projects detection
    this.criticalProjects = this.repositories
      .map(repo => {
        const latestScan = repo.scans.find(s => s.status === 'completed');
        const critical = latestScan?.summary?.critical || 0;
        return { repo, scan: latestScan!, criticalCount: critical };
      })
      .filter(item => item.criticalCount > 0);
  }

  selectScan(event: {repo: Repository, scan: Scan}) {
    this.selectedRepo = event.repo;
    this.selectedScan = event.scan;
    this.displayDetails = true;
  }

  closeModal() {
    this.displayDetails = false;
    this.selectedRepo = null;
    this.selectedScan = null;
  }

  getJson(obj: any): string {
    return obj ? JSON.stringify(obj, null, 2) : 'No data available.';
  }

  exportVex() {
    if (this.selectedRepo) this.api.exportOpenVex(this.selectedRepo.id);
  }

  downloadJson(data: any, filename: string) {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
  }

  downloadReport() {
    if (!this.selectedScan || !this.selectedScan.summary || !this.selectedRepo) return;
    const doc = new jsPDF() as any;
    const scan = this.selectedScan;
    const repo = this.selectedRepo;
    const summary = scan.summary;

    doc.setFillColor(30, 41, 59);
    doc.rect(0, 0, 210, 40, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(24);
    doc.setFont('helvetica', 'bold');
    doc.text('Zanshin Security Report', 14, 25);
    doc.setFontSize(10);
    doc.text(`Generated on ${new Date().toLocaleString()}`, 14, 33);

    doc.setTextColor(0, 0, 0);
    doc.setFontSize(16);
    doc.text('Target Information', 14, 55);
    doc.setDrawColor(226, 232, 240);
    doc.line(14, 58, 196, 58);

    doc.setFontSize(11);
    doc.text('Repository URL:', 14, 68);
    doc.text(repo.url, 50, 68);
    
    autoTable(doc, {
      startY: 110,
      head: [['Severity', 'Count', 'Description']],
      body: [
        ['CRITICAL', summary!.critical, 'Immediate threat.'],
        ['HIGH', summary!.high, 'Significant threat.'],
        ['MEDIUM', summary!.medium, 'Moderate threat.'],
        ['LOW', summary!.low, 'Minor threat.'],
      ],
      headStyles: { fillColor: [51, 65, 85] }
    });

    doc.save(`Zanshin_Report_${repo.id}_${scan.branch}.pdf`);
  }
}

