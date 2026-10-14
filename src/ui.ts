import { escapeHtml } from './security';

export const DISCONNECTED_CORE_LABEL = 'idle';

export interface ResolvedRuntimeInfo {
    platform: 'android' | 'desktop';
    version: string;
    updateRepo: string;
}

export function resolveRuntimeInfo(
    nativeInfo: Partial<ResolvedRuntimeInfo> | null,
    userAgent: string,
    buildVersion: string,
    defaultRepo: string,
): ResolvedRuntimeInfo {
    const androidWebView = /\bAndroid\b/i.test(userAgent);
    return {
        platform: androidWebView || nativeInfo?.platform === 'android' ? 'android' : 'desktop',
        version: buildVersion,
        updateRepo: nativeInfo?.updateRepo || defaultRepo,
    };
}

export type AndroidBackAction = 'close-dialog' | 'close-subpage' | 'close-profiles' | 'close-menu' | 'go-main' | 'arm-exit' | 'exit';

export function resolveAndroidBackAction(state: {
    dialogOpen: boolean;
    subpageOpen?: boolean;
    profilesOpen: boolean;
    menuOpen: boolean;
    activePageId: string;
    exitArmed: boolean;
}): AndroidBackAction {
    if (state.dialogOpen) return 'close-dialog';
    if (state.subpageOpen) return 'close-subpage';
    if (state.profilesOpen) return 'close-profiles';
    if (state.menuOpen) return 'close-menu';
    if (state.activePageId !== 'page-main') return 'go-main';
    return state.exitArmed ? 'exit' : 'arm-exit';
}

export function renderPatchNotes(text: string): string {
    const groups: Array<{ title?: string; items: string[] }> = [];

    for (const sourceLine of text.split(/\r?\n/)) {
        const line = sourceLine.trim();
        if (!line) continue;

        if (/^v\s*\d/i.test(line)) {
            groups.push({ title: line, items: [] });
            continue;
        }

        const item = line.replace(/^[•*-]\s*/, '');
        if (groups.length === 0) groups.push({ items: [] });
        groups[groups.length - 1].items.push(item);
    }

    return groups.map(group => `
        <section class="patch-release">
            ${group.title ? `<h4 class="patch-release-title">${escapeHtml(group.title)}</h4>` : ''}
            <div class="patch-release-items">
                ${group.items.map(item => `<div class="patch-release-item">${escapeHtml(item)}</div>`).join('')}
            </div>
        </section>
    `).join('');
}

interface ReleaseSection { title: string; items: string[] }
interface Release { title: string; summary: string[]; sections: ReleaseSection[] }

function parseChangelog(markdown: string): Release[] {

    const releases: Release[] = [];
    let release: Release | null = null;
    let section: ReleaseSection | null = null;

    for (const sourceLine of markdown.split(/\r?\n/)) {
        const line = sourceLine.trim();
        const version = line.match(/^## \[([^\]]+)](?:\s*-\s*(.+))?$/);
        if (version) {
            release = {
                title: `v ${version[1]}${version[2] ? ` — ${version[2]}` : ''}`,
                summary: [],
                sections: [],
            };
            releases.push(release);
            section = null;
            continue;
        }

        if (!release || !line || line.startsWith('# ')) continue;

        const category = line.match(/^###\s+(.+)$/);
        if (category) {
            section = { title: category[1], items: [] };
            release.sections.push(section);
            continue;
        }

        if (line.startsWith('- ')) {
            const item = line.slice(2).trim();
            if (!section) {
                section = { title: '', items: [] };
                release.sections.push(section);
            }
            section.items.push(item);
            continue;
        }

        if (!line.startsWith('[')) release.summary.push(line);
    }

    return releases;
}

export function changelogReleaseCount(markdown: string): number {
    return parseChangelog(markdown).length;
}

/** `limit` keeps only the newest releases (the changelog lists newest first). */
export function renderProjectChangelog(markdown: string, limit?: number): string {
    const parsed = parseChangelog(markdown);
    const releases = limit === undefined ? parsed : parsed.slice(0, Math.max(0, limit));

    return releases.map(item => `
        <section class="patch-release">
            <h4 class="patch-release-title">${escapeHtml(item.title)}</h4>
            ${item.summary.map(line => `<p class="patch-release-summary">${escapeHtml(line)}</p>`).join('')}
            ${item.sections.map(group => `
                <div class="patch-release-group">
                    ${group.title ? `<h5 class="patch-release-category">${escapeHtml(group.title)}</h5>` : ''}
                    <div class="patch-release-items">
                        ${group.items.map(change => `<div class="patch-release-item">${escapeHtml(change)}</div>`).join('')}
                    </div>
                </div>
            `).join('')}
        </section>
    `).join('');
}
