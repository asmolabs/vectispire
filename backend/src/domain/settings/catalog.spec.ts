import { SETTINGS_CATALOG, definitionFor, validate } from './catalog';

describe('settings catalog', () => {
    it("only exposes keys whose reader is a ported service", () => {
        // The file's rule: a form that accepts a value and does nothing with it is worse
        // than a form that does not offer it. Those keys have no reader yet — exposing
        // them would suggest a configuration that has no effect.
        // Every other setting now has its reader. What remains is the token, which is
        // absent not for want of a reader but **because it is a secret**: it is encrypted
        // at rest, and a form that redisplayed it would put it back on screen in the
        // clear.
        expect(definitionFor('ticket_token')).toBeUndefined();
    });

    it('gives every setting a type, a section and an explanation', () => {
        for (const definition of SETTINGS_CATALOG) {
            expect(definition.section).not.toBe('');
            expect(definition.label).not.toBe('');
            // The explanation carries what the setting does **not** do, which is the part
            // an operator cannot guess.
            expect(definition.help.length).toBeGreaterThan(40);
        }
    });

    it("does not carry the same key twice", () => {
        const keys = SETTINGS_CATALOG.map((definition) => definition.key);

        expect(new Set(keys).size).toBe(keys.length);
    });

    it('accepts its own default for every setting', () => {
        // The quiet trap: a default the validation would refuse would make the screen
        // impossible to save without changing something on it.
        for (const definition of SETTINGS_CATALOG) {
            expect(validate(definition, definition.default)).toBeNull();
        }
    });
});

describe('validate', () => {
    const boolean = definitionFor('enrichment_enabled')!;
    const integer = definitionFor('retention_max_age_days')!;
    const severity = definitionFor('notification_min_severity')!;

    it('refuses an approximate boolean', () => {
        expect(validate(boolean, 'true')).toBeNull();
        expect(validate(boolean, 'oui')).toMatch(/true/);
        expect(validate(boolean, '1')).not.toBeNull();
    });

    it('refuses an unreadable integer rather than reading it as zero', () => {
        // Zero means "no limit": a typo that read as zero would silently disable
        // retention.
        expect(validate(integer, '90')).toBeNull();
        expect(validate(integer, '0')).toBeNull();
        expect(validate(integer, '')).not.toBeNull();
        expect(validate(integer, 'quatre-vingt-dix')).not.toBeNull();
        expect(validate(integer, '-1')).not.toBeNull();
        expect(validate(integer, '1.5')).not.toBeNull();
    });

    it('refuses a severity outside the vocabulary', () => {
        // A value outside the vocabulary would propagate silently into the sorting, the
        // summary and the gate.
        expect(validate(severity, 'high')).toBeNull();
        expect(validate(severity, 'HIGH')).not.toBeNull();
        expect(validate(severity, 'grave')).not.toBeNull();
    });
});

describe('sensitive settings', () => {
    it("marks as sensitive every setting whose value is a capability", () => {
        // A Slack or Teams webhook URL is not configuration: whoever knows it can post in
        // the channel where the team awaits Zanshin's alerts. That is precisely the
        // channel where a forged message carries most weight.
        expect(definitionFor('notification_webhook_url')?.sensitive).toBe(true);
    });

    it("marks as sensitive what maps the internal network", () => {
        // Not a secret in the strict sense, but an unprivileged account has no reason to
        // discover the address of the internal GitLab or of the host running the model.
        expect(definitionFor('ticket_base_url')?.sensitive).toBe(true);
        expect(definitionFor('ai_review_ollama_url')?.sensitive).toBe(true);
    });

    it('leaves non-sensitive what says nothing beyond the behaviour', () => {
        // Marking everything sensitive would amount to marking nothing: the screen would
        // lose its ability to hide the values that matter, and would blank out perfectly
        // ordinary ones for a non-administrator with no secret at stake.
        expect(definitionFor('enrichment_enabled')?.sensitive).toBeFalsy();
        expect(definitionFor('retention_max_age_days')?.sensitive).toBeFalsy();
        expect(definitionFor('notification_min_severity')?.sensitive).toBeFalsy();
    });
});
