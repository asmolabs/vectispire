import { UnsafeUrlError, unsafeReason, validateOutboundUrl } from './url-guard';

/** A simulated DNS resolution: the tests must not depend on the network. */
function resolving(map: Record<string, string[]>) {
    return async (hostname: string) => map[hostname] ?? [];
}

const PUBLIC = resolving({ 'example.test': ['93.184.216.34'] });

describe('validateOutboundUrl', () => {
    it('accepts a public destination for a webhook', async () => {
        await expect(validateOutboundUrl('https://example.test/hook', { allowPrivate: false, resolve: PUBLIC })).resolves.toBe(
            'https://example.test/hook'
        );
    });

    it('refuses the metadata endpoint, even when private is allowed', async () => {
        // The classic target: it hands the instance's credentials to whoever asks.
        // Nothing legitimate lives in that range.
        await expect(validateOutboundUrl('http://169.254.169.254/latest/meta-data/', { allowPrivate: true })).rejects.toThrow(/link-local/);
    });

    it('refuses a name that resolves to link-local', async () => {
        // The obvious bypass: hide the address behind a name.
        await expect(
            validateOutboundUrl('http://metadata.internal/', { allowPrivate: true, resolve: resolving({ 'metadata.internal': ['169.254.169.254'] }) })
        ).rejects.toThrow(/link-local/);
    });

    it('refuses a private address when a public destination is expected', async () => {
        for (const address of ['10.0.0.5', '172.16.3.1', '192.168.1.10', '127.0.0.1', '100.64.0.1']) {
            await expect(
                validateOutboundUrl(`http://host.internal/`, { allowPrivate: false, resolve: resolving({ 'host.internal': [address] }) })
            ).rejects.toThrow(/private or local/);
        }
    });

    it('refuses a name where only one of the addresses is private', async () => {
        // Every address is checked, not the first: checking only one would let the other
        // through.
        await expect(
            validateOutboundUrl('https://double.test/', {
                allowPrivate: false,
                resolve: resolving({ 'double.test': ['93.184.216.34', '10.0.0.5'] })
            })
        ).rejects.toThrow(/private or local/);
    });

    it('accepts private for a local side-car', async () => {
        await expect(validateOutboundUrl('http://127.0.0.1:8000/scan', { allowPrivate: true })).resolves.toContain('127.0.0.1');
    });

    it('refuses a public destination when an internal one is required', async () => {
        // Ollama receives the source code: the risk is not internal, it is external. A
        // well-formed public URL is exactly what exfiltration looks like.
        await expect(
            validateOutboundUrl('https://example.test/api', { allowPrivate: true, requirePrivate: true, resolve: PUBLIC })
        ).rejects.toThrow(/receives source code/);
    });

    it('refuses an unresolvable name when an internal destination is required', async () => {
        // Failing open is defensible for "is this private?", not for "this must be": an
        // unresolvable name proves nothing.
        await expect(
            validateOutboundUrl('https://unknown.test/', { allowPrivate: true, requirePrivate: true, resolve: resolving({}) })
        ).rejects.toThrow(/could not be resolved/);
    });

    describe('disguised IPv6', () => {
        /**
         * **The bypass came from comparing strings.** `new URL()` normalizes an IPv6
         * address before we read it: `::ffff:127.0.0.1` comes back in the hexadecimal form
         * `::ffff:7f00:1`, which the regular expression matching did not see. The address
         * was then judged public and the webhook — whose guard expects precisely a public
         * destination — reached loopback.
         *
         * Each case below is a different spelling of the same address.
         */
        it.each([
            ['::ffff:127.0.0.1', 'wrapped IPv4, written in dotted decimal'],
            ['::ffff:7f00:1', 'the same, in the form `new URL()` returns'],
            ['::ffff:169.254.169.254', 'the metadata endpoint, wrapped'],
            ['::ffff:10.0.0.1', 'a private network, wrapped'],
            ['0:0:0:0:0:0:0:1', 'loopback written out in full'],
            ['64:ff9b::7f00:1', 'loopback through the NAT64 translation prefix']
        ])('refuses http://[%s] for a webhook — %s', async (address) => {
            await expect(validateOutboundUrl(`http://[${address}]/hook`, { allowPrivate: false })).rejects.toBeInstanceOf(UnsafeUrlError);
        });

        it('accepts a genuinely public IPv6, so that the refusal means something', async () => {
            await expect(validateOutboundUrl('https://[2606:4700:4700::1111]/hook', { allowPrivate: false })).resolves.toContain('2606');
        });

        it('refuses wrapped link-local even when private is allowed', async () => {
            // A local side-car is allowed to be private; it is never allowed to be the
            // metadata endpoint, under any spelling.
            await expect(validateOutboundUrl('http://[::ffff:169.254.169.254]/', { allowPrivate: true })).rejects.toThrow(/link-local/);
        });
    });

    it('refuses schemes other than http and https', async () => {
        for (const url of ['file:///etc/passwd', 'gopher://example.test/', 'ftp://example.test/']) {
            await expect(validateOutboundUrl(url, { allowPrivate: true })).rejects.toThrow(/scheme/);
        }
    });

    it('refuses an empty or unreadable value', async () => {
        await expect(validateOutboundUrl('', { allowPrivate: true })).rejects.toThrow(UnsafeUrlError);
        await expect(validateOutboundUrl('not a url', { allowPrivate: true })).rejects.toThrow(UnsafeUrlError);
    });

    it('accepts an unresolvable name for a webhook', async () => {
        // A DNS hiccup must not make the settings screen unusable, and the request itself
        // would fail anyway.
        await expect(validateOutboundUrl('https://unknown.test/hook', { allowPrivate: false, resolve: resolving({}) })).resolves.toBe(
            'https://unknown.test/hook'
        );
    });
});

describe('real resolution', () => {
    // **Without an injected `resolve`**, so going through `node:dns`. This case exists
    // because every other test in this file — and those of the notification and the
    // tickets — bypasses resolution: the day the real call stopped working, not one of
    // them noticed. A guard that throws instead of validating refuses *every*
    // destination, which reads in operation as "the webhook never fires".
    it('validates a literal address without throwing', async () => {
        await expect(validateOutboundUrl('http://127.0.0.1:8000/', { allowPrivate: true })).resolves.toContain('127.0.0.1');
        await expect(validateOutboundUrl('https://93.184.216.34/', { allowPrivate: false })).resolves.toContain('93.184.216.34');
    });

    it('goes through DNS resolution for a name', async () => {
        // The name does not need to exist: what matters is that the call reaches a
        // decision instead of blowing up.
        await expect(validateOutboundUrl('https://nonexistent-host.invalid/hook', { allowPrivate: false })).resolves.toBe(
            'https://nonexistent-host.invalid/hook'
        );
    });
});

describe('unsafeReason', () => {
    it('returns the reason instead of throwing', async () => {
        expect(await unsafeReason('https://example.test/', { allowPrivate: false, resolve: PUBLIC })).toBeNull();
        expect(await unsafeReason('http://10.0.0.1/', { allowPrivate: false })).toMatch(/private or local/);
    });
});
