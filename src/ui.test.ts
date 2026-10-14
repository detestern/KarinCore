import { describe, expect, it } from 'vitest';
import { changelogReleaseCount, DISCONNECTED_CORE_LABEL, renderPatchNotes, renderProjectChangelog, resolveAndroidBackAction, resolveRuntimeInfo } from './ui';

describe('runtime metadata fallback', () => {
    it('keeps Android layout and the build version when the native command fails', () => {
        expect(resolveRuntimeInfo(null, 'Mozilla/5.0 (Linux; Android 15) wv', '0.1.0-alpha.31', 'owner/repo')).toEqual({
            platform: 'android',
            version: '0.1.0-alpha.31',
            updateRepo: 'owner/repo',
        });
    });

    it('does not allow stale native version metadata to replace the packaged version', () => {
        expect(resolveRuntimeInfo(
            { platform: 'desktop', version: '0.0.0', updateRepo: 'owner/repo' },
            'Mozilla/5.0 (Linux; Android 14) wv',
            '0.1.0-alpha.31',
            'owner/repo',
        )).toMatchObject({ platform: 'android', version: '0.1.0-alpha.31' });
    });
});

describe('mobile status presentation', () => {
    it('uses a user-facing idle state instead of leaking a null sentinel', () => {
        expect(DISCONNECTED_CORE_LABEL).toBe('idle');
        expect(DISCONNECTED_CORE_LABEL).not.toBe('null');
    });
});

describe('Android back navigation', () => {
    const baseState = {
        dialogOpen: false,
        profilesOpen: false,
        menuOpen: false,
        activePageId: 'page-main',
        exitArmed: false,
    };

    it('returns every secondary page to the main page', () => {
        expect(resolveAndroidBackAction({ ...baseState, activePageId: 'page-routing' })).toBe('go-main');
        expect(resolveAndroidBackAction({ ...baseState, activePageId: 'page-settings' })).toBe('go-main');
        expect(resolveAndroidBackAction({ ...baseState, activePageId: 'page-about' })).toBe('go-main');
    });

    it('requires a second press before exiting the main page', () => {
        expect(resolveAndroidBackAction(baseState)).toBe('arm-exit');
        expect(resolveAndroidBackAction({ ...baseState, exitArmed: true })).toBe('exit');
    });

    it('closes overlays before navigating or exiting', () => {
        expect(resolveAndroidBackAction({ ...baseState, dialogOpen: true })).toBe('close-dialog');
        expect(resolveAndroidBackAction({ ...baseState, subpageOpen: true })).toBe('close-subpage');
        expect(resolveAndroidBackAction({ ...baseState, subpageOpen: true, profilesOpen: true, menuOpen: true })).toBe('close-subpage');
        expect(resolveAndroidBackAction({ ...baseState, dialogOpen: true, subpageOpen: true })).toBe('close-dialog');
        expect(resolveAndroidBackAction({ ...baseState, profilesOpen: true })).toBe('close-profiles');
        expect(resolveAndroidBackAction({ ...baseState, menuOpen: true })).toBe('close-menu');
    });
});

describe('project changelog presentation', () => {
    it('renders repository releases, categories and changes as structured blocks', () => {
        const html = renderProjectChangelog(`# Changelog\n\n## Unreleased\n\n## [0.1.0-alpha.2] - 2026-10-08\n\nOwn release.\n\n### Added\n- First project change\n### Fixed\n- Second project change`);

        expect(html).toContain('v 0.1.0-alpha.2 — 2026-10-08');
        expect(html).toContain('Own release.');
        expect(html).toContain('Added');
        expect(html.match(/class="patch-release-item"/g)).toHaveLength(2);
        expect(html).not.toContain('Unreleased');
    });

    it('can limit the output to the newest releases', () => {
        const md = '## [3.0.0]\n- c\n## [2.0.0]\n- b\n## [1.0.0]\n- a';
        expect(changelogReleaseCount(md)).toBe(3);
        const html = renderProjectChangelog(md, 1);
        expect(html).toContain('v 3.0.0');
        expect(html).not.toContain('v 2.0.0');
        expect(renderProjectChangelog(md).match(/class="patch-release"/g)).toHaveLength(3);
    });

    it('escapes changelog content', () => {
        expect(renderProjectChangelog('## [1.0.0]\n### Fixed\n- <script>alert(1)</script>')).not.toContain('<script>');
    });
});

describe('patch notes presentation', () => {
    it('turns versions and bullets into separate readable blocks', () => {
        const html = renderPatchNotes('v 1.2.0 — Release\n• First change\n• Second change\n\nv 1.1.0\n• Previous change');

        expect(html.match(/patch-release-title/g)).toHaveLength(2);
        expect(html.match(/class="patch-release-item"/g)).toHaveLength(3);
        expect(html).toContain('First change');
    });

    it('escapes translated patch-note content', () => {
        expect(renderPatchNotes('v 1.0\n• <img src=x onerror=alert(1)>')).not.toContain('<img');
    });
});
