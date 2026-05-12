import { Component, Input, Output, EventEmitter, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService, Repository, Scan } from '../api';
import { VulnerabilityTableComponent } from '../vulnerability-table/vulnerability-table';
import { DialogModule } from 'primeng/dialog';
import { ButtonModule } from 'primeng/button';
import { TabsModule } from 'primeng/tabs';
import { TableModule } from 'primeng/table';
import { InputTextModule } from 'primeng/inputtext';
import { TagModule } from 'primeng/tag';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

@Component({
  selector: 'app-scan-details',
  standalone: true,
  imports: [
    CommonModule,
    DialogModule,
    ButtonModule,
    TabsModule,
    TableModule,
    InputTextModule,
    TagModule,
    VulnerabilityTableComponent,
  ],
  template: `
    <p-dialog 
      [(visible)]="display" 
      [modal]="true" 
      [header]="repo?.url || 'Scan Details'"
      [style]="{ width: '80vw' }" 
      [breakpoints]="{ '960px': '95vw' }"
      [draggable]="false" 
      [resizable]="false"
      appendTo="body"
      (onHide)="closeModal()">
      
      <div *ngIf="scan" class="p-fluid mt-2">
        <div *ngIf="scan.status === 'failed'" class="p-3 border-round-xl bg-red-50 border-red-100 border-1 mb-4 shadow-sm">
          <div class="flex align-items-center gap-2 text-red-700 font-bold mb-2">
            <i class="pi pi-exclamation-triangle"></i>
            <span>L'analyse a échoué</span>
          </div>
          <div class="p-2 bg-white-alpha-50 border-round text-red-600 text-sm font-monospace overflow-auto" style="max-height: 150px;">
            {{ scan.error || 'Aucune information d\\'erreur détaillée n\\'est disponible.' }}
          </div>
        </div>

        <div class="flex flex-column md:flex-row justify-content-between align-items-start md:align-items-center mb-4 gap-2">
          <div>
            <div class="flex align-items-center gap-3 mb-1">
              <p class="text-secondary mb-0">Branch: <span class="text-primary font-bold">{{ scan.branch }}</span></p>
              <p class="text-secondary mb-0" *ngIf="scan.version">Version: <span class="bg-blue-50 text-blue-700 px-2 py-1 border-round text-xs font-bold">{{ scan.version }}</span></p>
              <p class="text-secondary mb-0" *ngIf="scan.projectType">Type: <span class="bg-gray-100 text-gray-700 px-2 py-1 border-round text-xs font-bold">{{ scan.projectType }}</span></p>
            </div>
            <p class="text-secondary mb-0" *ngIf="scan.subPath">Path: <span class="text-primary font-bold">{{ scan.subPath }}</span></p>
          </div>
          <div class="flex flex-wrap gap-2">
            <p-button label="Export OpenVEX" icon="pi pi-download" severity="secondary" size="small" (click)="exportVex()" *ngIf="repo"></p-button>
            <p-button label="Download PDF" icon="pi pi-file-pdf" severity="success" size="small" (click)="downloadReport()" *ngIf="scan.status === 'completed'"></p-button>
            <p-button label="Download SBOM" icon="pi pi-download" severity="info" size="small" (click)="downloadJson(scan.sbom, 'sbom.json')" *ngIf="scan.sbom"></p-button>
            <p-button label="Download CVEs" icon="pi pi-download" severity="warn" size="small" (click)="downloadJson(scan.cves, 'cves.json')" *ngIf="scan.cves"></p-button>
          </div>
        </div>

        <p-tabs value="0">
          <p-tablist>
            <p-tab value="0">Summary</p-tab>
            <p-tab value="1">Findings ({{ scan.findingsCount || 0 }})</p-tab>
            <p-tab value="4">Dependencies ({{ artifacts.length }})</p-tab>
            <p-tab value="2">Grype (CVEs)</p-tab>
            <p-tab value="3">Syft (SBOM)</p-tab>
          </p-tablist>
          <p-tabpanels>
            <p-tabpanel value="0">
              <div class="grid text-center mt-3" *ngIf="scan.summary">
                <div class="col-12 md:col-3">
                  <div class="p-3 border-round-xl surface-border border-1 bg-red-50">
                    <span class="text-4xl font-bold text-red-600 block mb-2">{{ scan.summary.critical }}</span>
                    <span class="text-red-500 font-semibold uppercase text-xs">Critical</span>
                  </div>
                </div>
                <div class="col-12 md:col-3">
                  <div class="p-3 border-round-xl surface-border border-1 bg-orange-50">
                    <span class="text-4xl font-bold text-orange-600 block mb-2">{{ scan.summary.high }}</span>
                    <span class="text-orange-500 font-semibold uppercase text-xs">High</span>
                  </div>
                </div>
                <div class="col-12 md:col-3">
                  <div class="p-3 border-round-xl surface-border border-1 bg-yellow-50">
                    <span class="text-4xl font-bold text-yellow-600 block mb-2">{{ scan.summary.medium }}</span>
                    <span class="text-yellow-500 font-semibold uppercase text-xs">Medium</span>
                  </div>
                </div>
                <div class="col-12 md:col-3">
                  <div class="p-3 border-round-xl surface-border border-1 bg-blue-50">
                    <span class="text-4xl font-bold text-blue-600 block mb-2">{{ scan.summary.low }}</span>
                    <span class="text-blue-500 font-semibold uppercase text-xs">Low</span>
                  </div>
                </div>
              </div>
              
              <div class="mt-4" *ngIf="scan.summary">
                <h6 class="font-bold text-lg mb-2">Quick Overview</h6>
                <p class="m-0">This branch analysis contains <strong>{{ scan.findingsCount || 0 }}</strong> total vulnerabilities.</p>
                <p *ngIf="scan.durationMs" class="text-secondary text-sm mt-3">Scan completed in {{ (scan.durationMs / 1000).toFixed(2) }} seconds.</p>
              </div>
            </p-tabpanel>
            
            <p-tabpanel value="1">
              <div class="mt-3">
                <app-vulnerability-table [cves]="scan.cves" [repositoryId]="repo?.id!"></app-vulnerability-table>
              </div>
            </p-tabpanel>

            <p-tabpanel value="4">
              <div class="mt-3">
                <p-table #dtDeps [value]="artifacts" [paginator]="true" [rows]="10" 
                         [rowsPerPageOptions]="[10, 25, 50, 100]"
                         styleClass="p-datatable-sm border-round"
                         [globalFilterFields]="['name', 'version', 'type', 'language']"
                         responsiveLayout="scroll" [rowHover]="true">
                  <ng-template pTemplate="caption">
                    <div class="flex flex-column sm:flex-row justify-content-between align-items-start sm:align-items-center gap-3 p-1">
                      <div class="flex align-items-center">
                        <i class="pi pi-box text-primary mr-2"></i>
                        <span class="font-bold text-lg text-900">Dépendances découvertes ({{ artifacts.length }})</span>
                      </div>
                      <span class="p-input-icon-left w-full sm:w-auto">
                        <i class="pi pi-search"></i>
                        <input pInputText type="text" (input)="dtDeps.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher un paquet..." class="p-inputtext-sm w-full" />
                      </span>
                    </div>
                  </ng-template>
                  <ng-template pTemplate="header">
                    <tr>
                      <th pSortableColumn="name">Nom / Paquet <p-sortIcon field="name"></p-sortIcon></th>
                      <th pSortableColumn="version" style="width: 20%">Version <p-sortIcon field="version"></p-sortIcon></th>
                      <th pSortableColumn="type" style="width: 150px">Type <p-sortIcon field="type"></p-sortIcon></th>
                      <th pSortableColumn="language" style="width: 150px">Langage <p-sortIcon field="language"></p-sortIcon></th>
                    </tr>
                  </ng-template>
                  <ng-template pTemplate="body" let-pkg>
                    <tr class="hover:surface-50 transition-colors">
                      <td>
                        <div class="flex align-items-center gap-2">
                          <i class="pi pi-package text-secondary"></i>
                          <span class="font-bold text-900">{{ pkg.name }}</span>
                        </div>
                      </td>
                      <td><code class="text-xs surface-100 p-1 border-round">{{ pkg.version }}</code></td>
                      <td>
                        <span class="text-xs px-2 py-1 surface-200 border-round font-medium uppercase">{{ pkg.type }}</span>
                      </td>
                      <td>
                        <p-tag [value]="pkg.language || '—'" severity="secondary" [rounded]="true" styleClass="text-xs"></p-tag>
                      </td>
                    </tr>
                  </ng-template>
                  <ng-template pTemplate="emptymessage">
                    <tr>
                      <td colspan="4" class="text-center p-5 text-secondary">
                        <i class="pi pi-search text-4xl block mb-3"></i>
                        Aucune dépendance trouvée correspondant à votre recherche.
                      </td>
                    </tr>
                  </ng-template>
                </p-table>
              </div>
            </p-tabpanel>

            <p-tabpanel value="2">
              <pre class="bg-gray-900 p-3 border-round text-blue-400 overflow-auto mt-3" style="max-height: 400px;">{{ getJson(scan.cves) }}</pre>
            </p-tabpanel>
            
            <p-tabpanel value="3">
              <pre class="bg-gray-900 p-3 border-round text-purple-400 overflow-auto mt-3" style="max-height: 400px;">{{ getJson(scan.sbom) }}</pre>
            </p-tabpanel>
          </p-tabpanels>
        </p-tabs>
      </div>
    </p-dialog>
  `,
  styles: [`
    pre { white-space: pre-wrap; word-break: break-all; }
  `]
})
export class ScanDetailsComponent {
  private api = inject(ApiService);

  @Input() display = false;
  @Input() repo: Repository | null = null;
  @Input() scan: Scan | null = null;
  @Output() displayChange = new EventEmitter<boolean>();

  closeModal() {
    this.display = false;
    this.displayChange.emit(false);
  }

  get artifacts(): any[] {
    return this.scan?.sbom?.artifacts || [];
  }

  getJson(obj: any): string {
    return obj ? JSON.stringify(obj, null, 2) : 'No data available.';
  }

  exportVex() {
    if (this.repo) this.api.exportOpenVex(this.repo.id);
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

  async downloadReport() {
    if (!this.scan || !this.scan.summary || !this.repo) return;
    
    // Fetch latest VEX decisions to include in report
    const decisions = await this.api.getVexDecisions(this.repo.id).toPromise() || [];
    const decisionsMap = new Map();
    decisions.forEach(d => decisionsMap.set(`${d.vulnerabilityId}-${d.packageName}`, d));

    const doc = new jsPDF() as any;
    const scan = this.scan;
    const repo = this.repo;
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
    
    // Add VEX Triage section if decisions exist
    if (decisions.length > 0) {
      doc.addPage();
      doc.setFillColor(30, 41, 59);
      doc.rect(0, 0, 210, 20, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(14);
      doc.text('Manual Triage Decisions (VEX)', 14, 13);
      
      doc.setTextColor(0, 0, 0);
      autoTable(doc, {
        startY: 30,
        head: [['CVE ID', 'Package', 'Status', 'Response', 'Comment']],
        body: decisions.map(d => [
          d.vulnerabilityId,
          d.packageName,
          d.status.replace(/_/g, ' ').toUpperCase(),
          d.response ? d.response.replace(/_/g, ' ') : '—',
          d.comment || '—'
        ]),
        headStyles: { fillColor: [51, 65, 85] },
        columnStyles: {
            0: { fontStyle: 'bold' },
            4: { fontSize: 9 }
        }
      });
    }

    doc.save(`Zanshin_Report_${this.repo.name || this.repo.id}_${scan.branch}.pdf`);
  }
}
