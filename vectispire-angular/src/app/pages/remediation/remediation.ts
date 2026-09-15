import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '@/app/core/api.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import { SelectModule } from '@openng/optimus-ui/select';
import { FormsModule } from '@angular/forms';
import type { HighImpactFix, MonitoredContainer, MonitoredRepository, RemediationCoverage, SecurityDebtReport } from '@/app/core/api.models';

/**
 * Ce qu'il faut faire, dans l'ordre — et non ce qui ne va pas.
 *
 * <p><b>Le calcul existait, l'écran n'existait pas.</b> {@code /api/v1/remediation/high-impact-fixes}
 * classe les mises à jour par ce qu'elles ferment sur ce qu'elles coûtent, et
 * {@code getHighImpactFixes} attendait dans le service front sans qu'aucun composant ne l'appelle.
 * Le produit savait donc répondre à « par quoi je commence » et ne le disait à personne : le
 * tableau de bord en montrait un extrait dans une carte, entre huit autres.
 *
 * <p><b>Une action par ligne, et non une vulnérabilité par ligne.</b> C'est la différence avec la
 * liste des constats. Quatorze constats de la même bibliothèque sur six dépôts ne sont pas
 * quatorze décisions : c'est une montée de version. La liste des constats répond « qu'est-ce qui
 * ne va pas », celle-ci répond « qu'est-ce que je fais lundi matin », et une équipe qui n'a que la
 * première trie du bruit au lieu de réduire du risque.
 *
 * <p><b>La dette est en tête parce qu'elle donne l'échelle.</b> Un ordre de travail sans total se
 * lit comme une liste infinie ; savoir que les dix premières lignes ferment la moitié du parc est
 * ce qui fait commencer.
 */
@Component({
    selector: 'app-remediation',
    standalone: true,
    imports: [CommonModule, RouterLink, FormsModule, ButtonModule, MessageModule, SelectModule, TagModule, TranslatePipe],
    templateUrl: './remediation.html'
})
export class Remediation {
    private readonly api = inject(ApiService);

    readonly fixes = signal<HighImpactFix[]>([]);
    readonly debt = signal<SecurityDebtReport | null>(null);

    /**
     * L'aveu du plan : ce qu'une montée de version ne fermera pas.
     *
     * <p><b>Parce qu'un utilisateur a lu une panne là où il y avait un calcul juste.</b> Un dépôt
     * dont le retard est fait de secrets exposés affiche une seule action face à des centaines de
     * constats ouverts — c'est exact, le classement ne retient que les vulnérabilités portant un
     * paquet, et rien à l'écran ne le disait. Un chiffre faux se corrige ; une défiance se garde.
     */
    readonly coverage = signal<RemediationCoverage | null>(null);
    readonly loading = signal(true);
    readonly error = signal<string | null>(null);
    readonly expanded = signal<string | null>(null);

    /**
     * La cible sur laquelle porte le plan, ou tout le parc.
     *
     * <p>Une seule liste déroulante pour les dépôts et les images : la question est « de quoi
     * suis-je responsable lundi », et elle ne se pose pas différemment selon qu'on livre un dépôt
     * ou une image. La valeur porte son genre pour que l'appel sache quel paramètre poser.
     */
    readonly targets = signal<{ label: string; value: string }[]>([]);
    scope = '';

    /**
     * Combien de lignes sont demandées.
     *
     * <p><b>Dix par défaut, et non « tout ».</b> Un ordre de travail court est ce qui fait
     * commencer ; c'est aussi pour cela que ceci grandit par paliers au lieu d'offrir une
     * pagination — personne ne veut la page 4 d'un plan de remédiation, on veut savoir ce qui
     * vient après les dix premières.
     */
    readonly wanted = signal(10);
    readonly CEILING = 50;

    /** Vrai tant que le serveur en a rendu autant qu'on en demandait : il y a peut-être la suite. */
    readonly mayHaveMore = computed(() =>
        this.wanted() < this.CEILING && this.fixes().length >= this.wanted());

    /**
     * Ce que les lignes affichées ferment, additionné.
     *
     * <p>Un même CVE peut apparaître sous deux paquets ; ce total compte donc des constats et non
     * des vulnérabilités distinctes, et le libellé le dit.
     */
    readonly closedByTheList = computed(() =>
        this.fixes().reduce((sum, fix) => sum + fix.cveCountResolved, 0));

    readonly hoursOfTheList = computed(() =>
        Math.round(this.fixes().reduce((sum, fix) => sum + fix.estimatedHours, 0) * 10) / 10);

    constructor() {
        this.load();

        // Les cibles sont chargées à part : ne pas pouvoir les lister n'empêche pas de lire le
        // plan du parc entier, qui est ce que la page montre par défaut.
        this.api.repositories().subscribe({
            next: (repositories: MonitoredRepository[]) => this.addTargets(
                repositories.map((repository) => ({
                    label: repository.name ?? repository.url,
                    value: `repo:${repository.id}`
                }))),
            error: () => {}
        });
        this.api.containers().subscribe({
            next: (containers: MonitoredContainer[]) => this.addTargets(
                containers.map((container) => ({
                    label: `${container.imageName}:${container.tag}`,
                    value: `container:${container.id}`
                }))),
            error: () => {}
        });
    }

    private addTargets(more: { label: string; value: string }[]): void {
        this.targets.update((current) => [...current, ...more]);
    }

    /** Recharge le plan pour la portée et la taille demandées. */
    load(): void {
        this.loading.set(true);
        this.error.set(null);

        const [kind, id] = this.scope ? this.scope.split(':') : [null, null];
        const repoId = kind === 'repo' ? Number(id) : undefined;
        const containerId = kind === 'container' ? Number(id) : undefined;

        this.api.getHighImpactFixes(repoId, containerId, this.wanted()).subscribe({
            next: (fixes) => { this.fixes.set(fixes); this.loading.set(false); },
            error: () => {
                this.error.set('Le plan de remédiation n\'a pas pu être calculé.');
                this.loading.set(false);
            }
        });

        // Séparément : une dette indisponible ne doit pas effacer un ordre de travail qui, lui,
        // est arrivé. C'est le contexte de la page, pas son sujet.
        this.api.getSecurityDebt(repoId, containerId)
            .subscribe({ next: (debt) => this.debt.set(debt), error: () => {} });

        // Et l'aveu de même : ne pas savoir ce que le plan laisse de côté vaut mieux que ne pas
        // voir le plan. Remis à zéro d'abord, pour qu'une portée ne garde pas l'aveu de l'autre.
        this.coverage.set(null);
        this.api.getRemediationCoverage(repoId, containerId)
            .subscribe({ next: (coverage) => this.coverage.set(coverage), error: () => {} });
    }

    /** Change de cible : la taille demandée repart à dix, le plan n'étant plus le même. */
    changeScope(): void {
        this.wanted.set(10);
        this.expanded.set(null);
        this.load();
    }

    showMore(): void {
        this.wanted.update((current) => Math.min(current * 2 + 5, this.CEILING));
        this.load();
    }

    toggle(fix: HighImpactFix): void {
        this.expanded.set(this.expanded() === fix.packageName ? null : fix.packageName);
    }

    isExpanded(fix: HighImpactFix): boolean {
        return this.expanded() === fix.packageName;
    }

    /**
     * La sévérité qui commande la ligne, pour la teinte.
     *
     * <p>Une seule critique décide de la couleur : c'est elle qui décide de l'urgence, et une
     * moyenne l'aurait diluée dans le nombre.
     */
    severityOf(fix: HighImpactFix): 'danger' | 'warn' | 'info' {
        if (fix.criticalCveCount > 0) return 'danger';
        if (fix.highCveCount > 0) return 'warn';
        return 'info';
    }
}
