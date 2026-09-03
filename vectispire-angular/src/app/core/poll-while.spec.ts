import { TestBed } from '@angular/core/testing';
import { Component, signal } from '@angular/core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { anyScanRunning, pollWhile } from './poll-while';

/**
 * Le compteur conditionnel.
 *
 * <p>Deux façons de se tromper, et une seule se voit. Un compteur qui ne démarre jamais se
 * remarque au premier scan lancé. Un compteur qui ne s'arrête <em>jamais</em> ne se remarque pas
 * du tout : l'écran marche, et le serveur reçoit sept cent vingt requêtes par heure et par onglet.
 * C'est le défaut que cet utilitaire remplace, donc chaque cas vérifie les deux sens.
 */
describe('pollWhile', () => {
    beforeEach(() => vi.useFakeTimers());
    afterEach(() => vi.useRealTimers());

    function mount(active: ReturnType<typeof signal<boolean>>, refresh: () => void) {
        @Component({ standalone: true, template: '' })
        class Host {
            constructor() {
                pollWhile(active, refresh, 1000);
            }
        }
        const fixture = TestBed.createComponent(Host);
        fixture.detectChanges();
        return fixture;
    }

    it('ne demande rien tant que rien ne bouge', () => {
        const refresh = vi.fn();
        mount(signal(false), refresh);

        vi.advanceTimersByTime(10_000);
        expect(refresh).not.toHaveBeenCalled();
    });

    it("rafraîchit tant que ça bouge, et se tait dès que c'est réglé", () => {
        const refresh = vi.fn();
        const active = signal(true);
        const fixture = mount(active, refresh);

        vi.advanceTimersByTime(3000);
        expect(refresh).toHaveBeenCalledTimes(3);

        active.set(false);
        fixture.detectChanges();
        vi.advanceTimersByTime(10_000);
        expect(refresh).toHaveBeenCalledTimes(3);
    });

    it('redémarre quand un nouveau scan est lancé', () => {
        const refresh = vi.fn();
        const active = signal(false);
        const fixture = mount(active, refresh);

        vi.advanceTimersByTime(5000);
        expect(refresh).not.toHaveBeenCalled();

        active.set(true);
        fixture.detectChanges();
        vi.advanceTimersByTime(2000);
        expect(refresh).toHaveBeenCalledTimes(2);
    });

    it("s'arrête avec l'écran, pas après lui", () => {
        // Un intervalle qui survit à son composant continue d'appeler le serveur pour personne,
        // et rien à l'écran ne le montre.
        const refresh = vi.fn();
        const fixture = mount(signal(true), refresh);

        vi.advanceTimersByTime(2000);
        expect(refresh).toHaveBeenCalledTimes(2);

        fixture.destroy();
        vi.advanceTimersByTime(10_000);
        expect(refresh).toHaveBeenCalledTimes(2);
    });
});

describe('anyScanRunning', () => {
    it('ne compte que les statuts qui bougent encore', () => {
        expect(anyScanRunning([{ status: 'completed' }, { status: 'failed' }])).toBe(false);
        expect(anyScanRunning([{ status: 'completed' }, { status: 'pending' }])).toBe(true);
        expect(anyScanRunning([{ status: 'SCANNING' }])).toBe(true);
        // Une cible jamais scannée n'attend rien : sans ce cas, une liste neuve interrogerait le
        // serveur pour toujours.
        expect(anyScanRunning([null, undefined, {}])).toBe(false);
        expect(anyScanRunning([])).toBe(false);
    });
});
