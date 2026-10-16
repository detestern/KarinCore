import { invoke } from "@tauri-apps/api/core";

// **********************************
// ВКЛАДКА «ДИАГНОСТИКА»
// Проверки идут по цепочке: интернет, DNS, порт сервера, запрос через туннель.
// Что именно сломалось, решает Rust (diag::verdict); здесь только порядок проб и тексты.
// **********************************

export interface AndroidState {
    vpnPermissionGranted: boolean;
    batteryOptimizationExempt: boolean;
    backgroundRestricted: boolean;
    lockdown: boolean;
}

export interface DiagContext {
    t: (key: string) => string;
    getLink: () => string | null;
    isConnected: () => boolean;
    /** Состояние Android: разрешение VPN, ограничения фона, блокировка подключений без VPN. */
    getAndroidState: () => Promise<AndroidState | null>;
    goTo: (pageId: string) => void;
    openProfiles: () => void;
    connect: () => void;
    restartCore: () => void;
    /** Обновляет подписку выбранного сервера. false — у сервера нет подписки, обновлять нечего. */
    updateSubscription: () => Promise<boolean>;
    requestVpnPermission: () => Promise<boolean>;
    openAndroidSettings: (target: 'vpn' | 'battery' | 'background') => void;
}

export type Transport = 'tcp' | 'other' | 'none';
export interface Endpoint { host: string; port: number; transport: Transport; }

type StepState = 'ok' | 'failed' | 'skipped';
interface TunnelProbe { state: string; ms: number; error: string; log: string[]; }
interface Verdict { code: string; detail: string; steps: StepState[]; }
interface Snapshot {
    verdict: Verdict;
    endpoint: Endpoint;
    tcpMs: number | null;
    tunnel: TunnelProbe | null;
    stalledStep: number | null;
    probes: Record<string, string>;
    link: string | null;
}

const STEP_KEYS = ['diag_step_internet', 'diag_step_dns', 'diag_step_port', 'diag_step_handshake', 'diag_step_tunnel'];
const PROBE_TIMEOUT_MS = 9000;

// Зелёная рамка, жёлтая (стоит обратить внимание) и красная (не работает).
const SEVERITY: Record<string, 'good' | 'warn' | 'fail'> = {
    ok: 'good',
    slow: 'warn',
    handshake_rejected: 'warn',
    vpn_off: 'warn',
    no_server: 'warn',
    killswitch_blocking: 'warn',
    background_restricted: 'warn',
    no_vpn_permission: 'warn',
    check_stalled: 'warn',
    no_internet: 'fail',
    dns_fail: 'fail',
    server_unreachable: 'fail',
    tunnel_no_traffic: 'fail',
    core_stopped: 'fail',
};

// Первое действие — главное, «Подробности» добавляются всегда.
const ACTIONS: Record<string, string[]> = {
    ok: [],
    slow: ['switch_server'],
    no_internet: ['retry'],
    dns_fail: ['open_routing'],
    server_unreachable: ['switch_server'],
    handshake_rejected: ['update_subscription'],
    tunnel_no_traffic: ['switch_server'],
    no_server: ['add_server'],
    vpn_off: ['connect'],
    check_stalled: ['retry'],
    core_stopped: ['restart_core'],
    killswitch_blocking: ['open_vpn_settings'],
    background_restricted: ['open_background_settings'],
    no_vpn_permission: ['grant_permission'],
};

function decodeBase64(value: string): string | null {
    try {
        const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
        const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
        const binary = atob(padded);
        const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
        return new TextDecoder().decode(bytes);
    } catch {
        return null;
    }
}

function stripBrackets(host: string): string {
    return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function validPort(value: unknown): number | null {
    const port = Number(value);
    return Number.isInteger(port) && port > 0 && port < 65536 ? port : null;
}

/** Адрес и порт сервера из ссылки. Для OpenVPN и WireGuard шаги порта пропускаются. */
export function extractEndpoint(link: string | null): Endpoint | null {
    if (!link) return null;
    if (link.startsWith('ovpn://') || link.startsWith('wg://')) return { host: '', port: 0, transport: 'other' };

    try {
        if (link.startsWith('vmess://')) {
            const json = decodeBase64(link.slice('vmess://'.length).split('#')[0]);
            if (!json) return null;
            const data = JSON.parse(json);
            const port = validPort(data.port);
            if (!data.add || port === null) return null;
            return { host: String(data.add), port, transport: 'tcp' };
        }

        if (link.startsWith('vless://') || link.startsWith('trojan://') || link.startsWith('ss://')) {
            const url = new URL(link);
            if (url.hostname) {
                const port = validPort(url.port || (link.startsWith('ss://') ? '' : '443'));
                if (port !== null) return { host: stripBrackets(url.hostname), port, transport: 'tcp' };
            }
            if (link.startsWith('ss://')) {
                // Старый формат: ss://base64(method:password@host:port)
                const decoded = decodeBase64(link.slice('ss://'.length).split('#')[0].split('?')[0]);
                const match = decoded?.match(/@(\[[^\]]+\]|[^:@]+):(\d+)$/);
                const port = match ? validPort(match[2]) : null;
                if (match && port !== null) return { host: stripBrackets(match[1]), port, transport: 'tcp' };
            }
        }
    } catch {
        return null;
    }
    return null;
}

/** Причины, которые видны только на Android: нет разрешения VPN и ограничения фоновой работы. */
function applyAndroidCauses(verdict: Verdict, android: AndroidState | null): Verdict {
    if (!android) return verdict;
    if (verdict.code === 'vpn_off' && !android.vpnPermissionGranted) {
        return { ...verdict, code: 'no_vpn_permission' };
    }
    if (verdict.code === 'core_stopped' && (android.backgroundRestricted || !android.batteryOptimizationExempt)) {
        return { ...verdict, code: 'background_restricted', detail: android.backgroundRestricted ? 'restricted' : 'battery' };
    }
    return verdict;
}

function isIpAddress(host: string): boolean {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

function withTimeout<T>(promise: Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
        const timer = window.setTimeout(() => reject(new Error('stalled')), PROBE_TIMEOUT_MS);
        promise.then(
            value => { window.clearTimeout(timer); resolve(value); },
            error => { window.clearTimeout(timer); reject(error); },
        );
    });
}

function escapeText(value: string): string {
    return value.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
}

export function initDiagnostics(ctx: DiagContext): { refreshText: () => void } {
    const runButton = document.getElementById('diag-run') as HTMLButtonElement | null;
    const serverLine = document.getElementById('diag-server');
    const stepsBox = document.getElementById('diag-steps');
    const resultBox = document.getElementById('diag-result');

    let running = false;
    let last: Snapshot | null = null;
    let detailsOpen = false;

    const fill = (text: string, values: Record<string, string | number>): string =>
        text.replace(/\{(\w+)\}/g, (_m, key: string) => (key in values ? String(values[key]) : `{${key}}`));

    function stepResultText(index: number, state: StepState | 'pending', snap: Snapshot | null): string {
        const t = ctx.t;
        if (state === 'pending') return t('diag_r_checking');
        if (state === 'skipped') return t('diag_r_skipped');
        if (index === 1 && snap?.probes.dns === 'na') return t('diag_r_not_needed');
        if (state === 'ok') {
            if (index === 2) return t('diag_r_open');
            if (index === 4 && snap?.tunnel) return fill(t('diag_ms'), { ms: snap.tunnel.ms });
            return t('diag_r_ok');
        }
        if (index === 2) return t('diag_r_not_open');
        if (index === 3) return t('diag_r_rejected');
        return t('diag_r_failed');
    }

    function renderSteps(states: (StepState | 'pending' | 'waiting')[], snap: Snapshot | null) {
        if (!stepsBox) return;
        stepsBox.innerHTML = STEP_KEYS.map((key, index) => {
            const state = states[index] ?? 'waiting';
            const cls = state === 'waiting' ? 'skipped' : state === 'pending' ? 'pending' : state;
            const icon = state === 'ok' ? '✓' : state === 'failed' ? '✕' : state === 'pending' ? '…' : '–';
            const text = state === 'waiting' ? '' : stepResultText(index, state, snap);
            return `<div class="diag-step ${cls}"><span class="diag-icon">${icon}</span><span class="diag-name">${escapeText(ctx.t(key))}</span><span class="diag-res">${escapeText(text)}</span></div>`;
        }).join('');
    }

    function describeServer(link: string | null, endpoint: Endpoint | null): string {
        if (!endpoint) return ctx.t('diag_server_none');
        const name = link ? decodeLinkName(link) : '';
        const where = endpoint.host ? `${endpoint.host}:${endpoint.port}` : '';
        return `${ctx.t('diag_server')} ${[name, where].filter(Boolean).join(' · ')}`;
    }

    function decodeLinkName(link: string): string {
        const hash = link.indexOf('#');
        if (hash < 0) return '';
        try { return decodeURIComponent(link.slice(hash + 1)); } catch { return ''; }
    }

    function detailsText(snap: Snapshot): string {
        const lines: string[] = [];
        snap.verdict.steps.forEach((state, index) => {
            lines.push(`${ctx.t(STEP_KEYS[index])}: ${state}`);
        });
        lines.push('');
        Object.entries(snap.probes).forEach(([name, value]) => lines.push(`${name}: ${value}`));
        if (snap.tunnel) {
            lines.push(`tunnel: ${snap.tunnel.state} ${snap.tunnel.ms} ms ${snap.tunnel.error}`.trim());
            if (snap.tunnel.log.length > 0) {
                lines.push('', '--- xray log ---', ...snap.tunnel.log);
            }
        }
        return lines.join('\n');
    }

    function renderResult() {
        if (!resultBox) return;
        if (!last) { resultBox.innerHTML = ''; return; }
        const { verdict, endpoint, tunnel, stalledStep } = last;
        const code = verdict.code;
        const values: Record<string, string | number> = {
            host: endpoint.host,
            port: endpoint.port,
            ms: tunnel?.ms ?? 0,
            step: stalledStep !== null ? ctx.t(STEP_KEYS[stalledStep]) : '',
            sec: PROBE_TIMEOUT_MS / 1000,
        };
        const whyKey = verdict.detail ? `diag_${code}_w_${verdict.detail}` : `diag_${code}_w`;
        const title = fill(ctx.t(`diag_${code}_t`), values);
        const why = fill(ctx.t(whyKey), values);

        const actions = ACTIONS[code] ?? [];
        const buttons = actions.map((action, index) =>
            `<button type="button" class="${index === 0 ? '' : 'secondary'}" data-diag-action="${action}">${escapeText(ctx.t(`diag_act_${action}`))}</button>`);
        buttons.push(`<button type="button" class="secondary" data-diag-action="details">${escapeText(ctx.t(detailsOpen ? 'diag_act_hide_details' : 'diag_act_details'))}</button>`);

        const details = detailsOpen ? `<pre class="diag-details">${escapeText(detailsText(last))}</pre>` : '';
        resultBox.innerHTML = `<div class="diag-result ${SEVERITY[code] ?? 'warn'}"><p class="diag-title">${escapeText(title)}</p><p class="diag-why">${escapeText(why)}</p><div class="diag-actions">${buttons.join('')}</div>${details}</div>`;
    }

    function renderIdle() {
        if (stepsBox) stepsBox.innerHTML = `<p class="diag-hint">${escapeText(ctx.t('diag_intro'))}</p>`;
        if (resultBox) resultBox.innerHTML = '';
        if (serverLine) serverLine.textContent = describeServer(ctx.getLink(), extractEndpoint(ctx.getLink()));
        if (runButton) runButton.textContent = ctx.t('diag_run');
    }

    async function probe<T>(call: () => Promise<T>, onStall: () => void): Promise<T | null> {
        try {
            return await withTimeout(call());
        } catch (error) {
            if (error instanceof Error && error.message === 'stalled') { onStall(); return null; }
            throw error;
        }
    }

    async function run() {
        if (running || !runButton) return;
        running = true;
        detailsOpen = false;
        runButton.disabled = true;
        runButton.textContent = ctx.t('diag_running');
        if (resultBox) resultBox.innerHTML = '';

        const link = ctx.getLink();
        const found = extractEndpoint(link);
        const endpoint: Endpoint = found ?? { host: '', port: 0, transport: 'none' };
        const vpnOn = ctx.isConnected();
        if (serverLine) serverLine.textContent = describeServer(link, found);

        const probes: Record<string, string> = {};
        const states: (StepState | 'pending' | 'waiting')[] = ['waiting', 'waiting', 'waiting', 'waiting', 'waiting'];
        let stalledStep: number | null = null;
        let tcpMs: number | null = null;
        let tunnel: TunnelProbe | null = null;
        const stall = (index: number) => () => { if (stalledStep === null) stalledStep = index; };

        renderSteps(states, null);
        const mark = (index: number, state: StepState | 'pending' | 'waiting') => { states[index] = state; renderSteps(states, null); };

        try {
            if (endpoint.transport !== 'none') {
                mark(0, 'pending');
                const internet = await probe(() => invoke<string>('diag_internet'), stall(0));
                probes.internet = internet ?? 'fail';
                mark(0, probes.internet === 'ok' ? 'ok' : 'failed');

                if (stalledStep === null) {
                    if (endpoint.transport === 'tcp' && !isIpAddress(endpoint.host)) {
                        mark(1, 'pending');
                        const dns = await probe(() => invoke<string>('diag_resolve', { host: endpoint.host }), stall(1));
                        probes.dns = dns ?? 'fail';
                        mark(1, probes.dns === 'ok' ? 'ok' : 'failed');
                    } else {
                        probes.dns = 'na';
                        mark(1, 'ok');
                    }
                }

                if (stalledStep === null && probes.dns !== 'fail' && endpoint.transport === 'tcp') {
                    mark(2, 'pending');
                    const tcp = await probe(() => invoke<string>('diag_tcp', { host: endpoint.host, port: endpoint.port }), stall(2));
                    const raw = tcp ?? 'timeout';
                    if (raw.startsWith('open:')) { probes.tcp = 'open'; tcpMs = Number(raw.slice(5)); } else { probes.tcp = raw; }
                    mark(2, probes.tcp === 'open' ? 'ok' : 'failed');
                } else {
                    probes.tcp = 'na';
                }

                const reachable = probes.tcp === 'open' || endpoint.transport === 'other';
                if (stalledStep === null && vpnOn && reachable) {
                    mark(3, 'pending');
                    mark(4, 'pending');
                    const result = await probe(() => invoke<TunnelProbe>('diag_tunnel'), stall(4));
                    tunnel = result;
                    probes.tunnel = result?.state ?? 'na';
                } else {
                    probes.tunnel = 'na';
                }
            }

            let core = 'na';
            if (vpnOn) core = await probe(() => invoke<string>('diag_core'), () => undefined) ?? 'na';
            const android = await ctx.getAndroidState();

            let verdict: Verdict;
            if (stalledStep !== null) {
                verdict = { code: 'check_stalled', detail: '', steps: ['skipped', 'skipped', 'skipped', 'skipped', 'skipped'] };
            } else {
                verdict = await invoke<Verdict>('diag_verdict', {
                    vpnOn,
                    transport: endpoint.transport,
                    internet: probes.internet ?? 'ok',
                    dns: probes.dns ?? 'na',
                    tcp: probes.tcp ?? 'na',
                    tunnel: probes.tunnel ?? 'na',
                    tunnelMs: tunnel?.ms ?? 0,
                    tunnelLog: tunnel?.log ?? [],
                    core,
                    killSwitch: android?.lockdown ?? false,
                });
                verdict = applyAndroidCauses(verdict, android);
            }
            probes.core = core;
            last = { verdict, endpoint, tcpMs, tunnel, stalledStep, probes, link };
            const finalSteps = stalledStep !== null
                ? states.map((s, i) => (i === stalledStep ? 'failed' : s === 'pending' || s === 'waiting' ? 'skipped' : s))
                : verdict.steps;
            renderSteps(finalSteps as StepState[], last);
            renderResult();
        } catch (error) {
            console.error('diagnostics failed', error);
            last = {
                verdict: { code: 'check_stalled', detail: '', steps: ['skipped', 'skipped', 'skipped', 'skipped', 'skipped'] },
                endpoint, tcpMs, tunnel, stalledStep: stalledStep ?? 0, probes, link,
            };
            renderSteps(['skipped', 'skipped', 'skipped', 'skipped', 'skipped'], last);
            renderResult();
        } finally {
            running = false;
            runButton.disabled = false;
            runButton.classList.add('secondary');
            runButton.textContent = ctx.t('diag_run_again');
        }
    }

    function handleAction(action: string) {
        if (action === 'details') { detailsOpen = !detailsOpen; renderResult(); return; }
        if (action === 'retry') { void run(); return; }
        if (action === 'update_subscription') {
            void (async () => {
                const refreshed = await ctx.updateSubscription();
                if (refreshed) { void run(); } else { ctx.goTo('page-main'); ctx.openProfiles(); }
            })();
            return;
        }
        if (action === 'switch_server' || action === 'add_server') { ctx.goTo('page-main'); ctx.openProfiles(); return; }
        if (action === 'open_routing') { ctx.goTo('page-routing'); return; }
        if (action === 'connect') { ctx.goTo('page-main'); ctx.connect(); return; }
        if (action === 'restart_core') { ctx.restartCore(); return; }
        if (action === 'open_vpn_settings') { ctx.openAndroidSettings('vpn'); return; }
        if (action === 'open_background_settings') {
            ctx.openAndroidSettings(last?.verdict.detail === 'battery' ? 'battery' : 'background');
            return;
        }
        if (action === 'grant_permission') {
            void ctx.requestVpnPermission().then(granted => { if (granted) void run(); });
        }
    }

    runButton?.addEventListener('click', () => { void run(); });
    resultBox?.addEventListener('click', event => {
        const button = (event.target as HTMLElement).closest('[data-diag-action]') as HTMLElement | null;
        if (button?.dataset.diagAction) handleAction(button.dataset.diagAction);
    });

    renderIdle();

    return {
        refreshText() {
            if (running) return;
            if (last) {
                if (serverLine) serverLine.textContent = describeServer(last.link, last.endpoint.transport === 'none' ? null : last.endpoint);
                renderSteps(last.stalledStep !== null
                    ? last.verdict.steps.map((_s, i) => (i === last!.stalledStep ? 'failed' : 'skipped'))
                    : last.verdict.steps, last);
                renderResult();
                if (runButton) runButton.textContent = ctx.t('diag_run_again');
            } else {
                renderIdle();
            }
        },
    };
}
