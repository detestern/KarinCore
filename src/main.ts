import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { translations } from "./i18n";
import { extractEndpoint, initDiagnostics } from "./diagnostics";

// **********************************
// TYPES & INTERFACES
// **********************************
interface ProxyGroup { id: string; name: string; pinned: boolean; isOpen: boolean; }
interface ProxyLink { id: string; url: string; pinned: boolean; groupId: string | null; }
interface DnsConfig { type: string, url: string, ip: string }
interface RouteProfile { id: string, name: string, defaultOutbound: string, rules: any, domDns?: DnsConfig, remDns?: DnsConfig, zonePriority?: ZoneKey[] }
interface RoutingRule { type: string; value: string; }
type ZoneKey = 'direct' | 'proxy' | 'block';
interface SubscriptionResult { links: string[]; importedRouting?: Record<ZoneKey, RoutingRule[]>; importedDns?: { domestic?: DnsConfig; remote?: DnsConfig }; importedDefaultOutbound?: string; importedProfileName?: string; }

// **********************************
// STATE MANAGEMENT & LOCAL STORAGE
// **********************************
function safeParse(key: string, fallback: any): any {
    try {
        const val = localStorage.getItem(key);
        if (!val) return fallback;
        const parsed = JSON.parse(val);
        return parsed !== null && parsed !== undefined ? parsed : fallback;
    } catch (e) {
        return fallback;
    }
}

let currentTheme = localStorage.getItem('karin_theme') || 'dark';
let currentLang = localStorage.getItem('karin_lang') || 'en';
let activeLink: string | null = sessionStorage.getItem('karin_active_link') || null;
let selectedProfileUrl: string | null = localStorage.getItem('karin_selected_profile') || null;
// Мостик для внешних оболочек (karin-shell / Brain Shell): таймер отложенной отправки снимка и последний известный IP.
let bridgeTimer: number | null = null;
let bridgeIp = '';
let allAvailableTags: string[] = [];
let currentZone: ZoneKey = 'proxy';
let defaultOutbound: ZoneKey = 'proxy';
let allowServerProxy = safeParse('karin_allow_server_proxy', false);
let allowProxyLan = safeParse('karin_allow_proxy_lan', false);
let isEditMode = false;
let selectedLinks = new Set<string>();
let selectedGroups = new Set<string>();
let logInterval: number | null = null; 

let zonePriority: ZoneKey[] = safeParse('karin_zone_priority', ['proxy', 'direct', 'block']);
let openZone: ZoneKey | null = null;
let activeRouteProfileId: string | null = localStorage.getItem('karin_active_route_profile');

const savedOutbound = localStorage.getItem('karin_default_outbound');
if (savedOutbound === 'direct' || savedOutbound === 'proxy' || savedOutbound === 'block') {
    defaultOutbound = savedOutbound;
}

let appGroups: ProxyGroup[] = safeParse('karin_groups', []);
if (!Array.isArray(appGroups)) appGroups = [];

let rawLinks = safeParse('karin_links', []);
if (!Array.isArray(rawLinks)) rawLinks = [];
let appLinks: ProxyLink[] = rawLinks.map((l: any) => {
    if (typeof l === 'string') return { id: 'link_' + Date.now() + Math.random(), url: l, pinned: false, groupId: null };
    if (!l.id) return { id: 'link_' + Date.now() + Math.random(), url: l.url, pinned: l.pinned || false, groupId: null };
    return l;
});

let routingState: Record<ZoneKey, RoutingRule[]> = safeParse('karin_routing', { direct: [], proxy: [], block: [] });
if (!routingState.direct) routingState.direct = [];
if (!routingState.proxy) routingState.proxy = [];
if (!routingState.block) routingState.block = [];

let routeProfiles: RouteProfile[] = safeParse('karin_route_profiles', []);
if (!Array.isArray(routeProfiles)) routeProfiles = [];
routeProfiles = routeProfiles.map(p => {
    if (!p.domDns) p.domDns = { type: "doh", url: "https://dns.yandex.ru/dns-query", ip: "77.88.8.8" };
    if (!p.remDns) p.remDns = { type: "doh", url: "https://1.1.1.1/dns-query", ip: "1.1.1.1" };
    if (!p.rules) p.rules = { direct: [], proxy: [], block: [] };
    if (!p.zonePriority) p.zonePriority = ['proxy', 'direct', 'block'];
    return p;
});

function saveData() {
    localStorage.setItem('karin_groups', JSON.stringify(appGroups));
    localStorage.setItem('karin_links', JSON.stringify(appLinks));
    scheduleBridgeSync();
}

function cleanEmptyGroups() { 
    appGroups = appGroups.filter(g => appLinks.some(l => l.groupId === g.id)); 
}

// **********************************
// DOM ELEMENTS
// **********************************
const logOutput = document.getElementById('log-output') as HTMLPreElement | null;
const toggleLogs = document.getElementById('toggle-logs') as HTMLInputElement | null;
const linkInput = document.getElementById('link-input') as HTMLInputElement | null;
const btnSave = document.getElementById('btn-save') as HTMLButtonElement | null;
const linksContainer = document.getElementById('links-container') as HTMLDivElement | null;
const statusText = document.getElementById('status-text') as HTMLSpanElement | null;
const btnDisconnect = document.getElementById('btn-disconnect') as HTMLButtonElement | null;
const btnPing = document.getElementById('btn-ping') as HTMLButtonElement | null;
const statusIpBox = document.getElementById('status-ip-box') as HTMLDivElement | null;
const statusIp = document.getElementById('status-ip') as HTMLSpanElement | null;
const defaultOutboundLabel = document.getElementById('default-outbound-label') as HTMLSpanElement | null;
const btnMenu = document.getElementById('btn-menu') as HTMLButtonElement | null;
const sidebar = document.getElementById('sidebar') as HTMLDivElement | null;
const overlay = document.getElementById('overlay') as HTMLDivElement | null;
const sidebarItems = document.querySelectorAll('.sidebar-item');
const pages = document.querySelectorAll('.page-view');
const btnEditMode = document.getElementById('btn-edit-mode') as HTMLButtonElement | null;
const editBar = document.getElementById('edit-bar') as HTMLDivElement | null;
const importBar = document.getElementById('import-bar') as HTMLDivElement | null;
const columns = document.querySelectorAll<HTMLElement>('.route-column');
const searchModal = document.getElementById('search-modal') as HTMLDialogElement | null;
const modalSearch = document.getElementById('modal-search') as HTMLInputElement | null;
const searchResults = document.getElementById('search-results') as HTMLDivElement | null;
const manualInput = document.getElementById('manual-input') as HTMLInputElement | null;
const themeToggle = document.getElementById('theme-toggle') as HTMLInputElement | null;
const themeLabel = document.getElementById('theme-label') as HTMLLabelElement | null;
const btnImportFile = document.getElementById('btn-import-file') as HTMLButtonElement | null;
const importFileInput = document.getElementById('import-file-input') as HTMLInputElement | null;
const toggleServerProxy = document.getElementById('toggle-server-proxy') as HTMLInputElement | null;

const domType = document.getElementById('dns-dom-type') as HTMLSelectElement | null;
const domUrl = document.getElementById('dns-dom-url') as HTMLInputElement | null;
const domIp = document.getElementById('dns-dom-ip') as HTMLInputElement | null;
const remType = document.getElementById('dns-rem-type') as HTMLSelectElement | null;
const remUrl = document.getElementById('dns-rem-url') as HTMLInputElement | null;
const remIp = document.getElementById('dns-rem-ip') as HTMLInputElement | null;

const zones = { 
    direct: document.getElementById('zone-direct') as HTMLDivElement | null, 
    proxy: document.getElementById('zone-proxy') as HTMLDivElement | null, 
    block: document.getElementById('zone-block') as HTMLDivElement | null 
};

const langBtn = document.getElementById('lang-select-btn') as HTMLDivElement | null;
const langLabel = document.getElementById('lang-select-label') as HTMLSpanElement | null;
const langMenu = document.getElementById('lang-menu') as HTMLDivElement | null;

const langNames: Record<string, string> = {
    en: "English", ru: "Русский", fr: "Français", tr: "Türkçe", zh: "中文"
};

// **********************************
// DRAG AND DROP (ROUTING PRIORITY)
// **********************************
function applyColumnOrder() {
    const container = document.getElementById('routing-grid');
    if (!container) return;
    
    container.querySelectorAll('.routing-arrow').forEach(el => el.remove());
    
    zonePriority.forEach((zone, index) => {
        const col = document.querySelector(`.route-column[data-zone="${zone}"]`) as HTMLElement;
        if (col) {
            col.style.flex = "1";
            col.style.minWidth = "0";
            container.appendChild(col); 
            
            if (index < zonePriority.length - 1) {
                const arrow = document.createElement('div');
                arrow.className = 'routing-arrow';
                arrow.textContent = '➔';
                arrow.style.cssText = 'display: flex; align-items: center; justify-content: center; color: var(--accent); font-weight: bold; font-size: 20px; opacity: 0.5; padding: 0 5px; user-select: none; pointer-events: none;';
                container.appendChild(arrow);
            }
        }
    });
}

function applyColumnOrderWithAnimation() {
    const container = document.getElementById('routing-grid');
    if (!container) return;

    // 1. Снимаем координаты ДО изменения DOM
    const cols = Array.from(container.querySelectorAll('.route-column')) as HTMLElement[];
    const firstRects: Record<string, DOMRect> = {};
    cols.forEach(col => {
        firstRects[col.dataset.zone!] = col.getBoundingClientRect();
    });

    // 2. Меняем DOM
    applyColumnOrder();

    // 3. Снимаем координаты ПОСЛЕ изменения DOM и анимируем (FLIP)
    const newCols = Array.from(container.querySelectorAll('.route-column')) as HTMLElement[];
    newCols.forEach(col => {
        const first = firstRects[col.dataset.zone!];
        const last = col.getBoundingClientRect();
        
        if (first && last) {
            const deltaX = first.left - last.left;
            if (deltaX !== 0) {
                // Телепортируем на старое место без анимации
                col.style.transition = 'none';
                col.style.transform = `translateX(${deltaX}px)`;
                
                // Форсируем перерисовку кадра
                col.getBoundingClientRect();
                
                // Плавно едем на новое место
                requestAnimationFrame(() => {
                    col.style.transition = 'transform 0.4s cubic-bezier(0.25, 1, 0.5, 1)';
                    col.style.transform = 'translateX(0)';
                });
            }
        }
    });
}

function initDragAndDrop() {
    const container = document.getElementById('routing-grid');
    if (!container) return;
    
    let draggedZone: ZoneKey | null = null;
    
    document.querySelectorAll<HTMLElement>('.route-column').forEach(col => {
        col.addEventListener('dragstart', (e: DragEvent) => {
            const target = (e.target as HTMLElement).closest('.route-column') as HTMLElement;
            if (!target) return;
            
            draggedZone = target.dataset.zone as ZoneKey;
            target.style.opacity = '0.3';
            
            if (e.dataTransfer) {
                e.dataTransfer.effectAllowed = 'move';
                e.dataTransfer.setData('text/plain', draggedZone);
            }
        });
        
        col.addEventListener('dragend', (e: DragEvent) => {
            const target = (e.target as HTMLElement).closest('.route-column') as HTMLElement;
            if (target) target.style.opacity = '1';
            
            document.querySelectorAll('.route-column').forEach(c => {
                c.classList.remove('drag-over-left', 'drag-over-right');
                (c as HTMLElement).style.transform = '';
            });
            draggedZone = null;
        });
    });

    // Единый строгий математический контроллер на контейнере
    container.addEventListener('dragover', (e: DragEvent) => {
        e.preventDefault(); 
        if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
        if (!draggedZone) return;

        const rect = container.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const slotWidth = rect.width / 3;
        
        let hoverIndex = Math.floor(mouseX / slotWidth);
        hoverIndex = Math.max(0, Math.min(2, hoverIndex)); // Ограничиваем от 0 до 2
        
        const fromIndex = zonePriority.indexOf(draggedZone);
        
        // Сбрасываем эффекты со всех
        document.querySelectorAll('.route-column').forEach(c => {
            c.classList.remove('drag-over-left', 'drag-over-right');
        });

        // Навешиваем эффект только на тот блок, место которого мы хотим занять
        if (hoverIndex !== fromIndex) {
            const targetZone = zonePriority[hoverIndex];
            const targetCol = document.querySelector(`.route-column[data-zone="${targetZone}"]`) as HTMLElement;
            
            if (targetCol) {
                if (hoverIndex < fromIndex) {
                    // Тянем ВЛЕВО -> блок уступает вправо, подсвечивая левый край
                    targetCol.classList.add('drag-over-left');
                } else {
                    // Тянем ВПРАВО -> блок уступает влево, подсвечивая правый край
                    targetCol.classList.add('drag-over-right');
                }
            }
        }
    });

    container.addEventListener('drop', (e: DragEvent) => {
        e.preventDefault();
        if (!draggedZone) return;
        
        document.querySelectorAll('.route-column').forEach(c => {
            c.classList.remove('drag-over-left', 'drag-over-right');
            (c as HTMLElement).style.opacity = '1';
        });

        const rect = container.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const slotWidth = rect.width / 3;
        let hoverIndex = Math.floor(mouseX / slotWidth);
        hoverIndex = Math.max(0, Math.min(2, hoverIndex));
        
        const fromIndex = zonePriority.indexOf(draggedZone);
        
        if (fromIndex !== hoverIndex) {
            zonePriority.splice(fromIndex, 1);
            zonePriority.splice(hoverIndex, 0, draggedZone);
            
            localStorage.setItem('karin_zone_priority', JSON.stringify(zonePriority));
            applyColumnOrderWithAnimation(); 
        }
        draggedZone = null;
    });
}

// **********************************
// SYSTEM FIXES (WEBKITGTK / WAYLAND ZOOM PREVENTION)
// **********************************
const preventNativeZoom = (e: Event) => {
    const wheelEvent = e as WheelEvent;
    const touchEvent = e as TouchEvent;
    const kbEvent = e as KeyboardEvent;

    if (e.type === 'keydown' && (kbEvent.ctrlKey || kbEvent.metaKey) && 
       (kbEvent.key === '+' || kbEvent.key === '-' || kbEvent.key === '=' || kbEvent.key === '0')) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    if ((e.type === 'wheel' || e.type === 'mousewheel' || e.type === 'DOMMouseScroll') && 
       (wheelEvent.ctrlKey || wheelEvent.metaKey)) {
        e.preventDefault();
        e.stopPropagation();
    }

    if (e.type === 'touchmove' && touchEvent.touches && touchEvent.touches.length > 1) {
        e.preventDefault();
        e.stopPropagation();
    }
};

window.addEventListener('keydown', preventNativeZoom, { capture: true });
window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !document.querySelector('dialog[open]') && closeZonePage()) e.preventDefault();
});
window.addEventListener('wheel', preventNativeZoom, { passive: false, capture: true });
window.addEventListener('mousewheel', preventNativeZoom, { passive: false, capture: true });
window.addEventListener('DOMMouseScroll', preventNativeZoom, { passive: false, capture: true });
window.addEventListener('touchmove', preventNativeZoom, { passive: false, capture: true });
window.addEventListener('gesturestart', (e) => { e.preventDefault(); e.stopPropagation(); }, { capture: true });
window.addEventListener('gesturechange', (e) => { e.preventDefault(); e.stopPropagation(); }, { capture: true });
window.addEventListener('gestureend', (e) => { e.preventDefault(); e.stopPropagation(); }, { capture: true });
window.addEventListener('beforeunload', () => { invoke('stop_proxy').catch(console.error); });

// **********************************
// INTERNATIONALIZATION (i18n)
// **********************************
function t(key: string): string { 
    return translations[currentLang]?.[key] || key; 
}

let diagnostics: { refreshText: () => void } | null = null;

function updateUIStrings() {
    document.querySelectorAll('[data-i18n]').forEach(el => { 
        const key = el.getAttribute('data-i18n'); 
        if (key) el.textContent = t(key); 
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => { 
        const key = el.getAttribute('data-i18n-placeholder'); 
        if (key) (el as HTMLInputElement).placeholder = t(key); 
    });
    diagnostics?.refreshText();
}

// **********************************
// KARIN TERMINAL ASSISTANT LOGIC
// **********************************
const karinConsole = document.getElementById('karin-msg') as HTMLSpanElement | null;
let karinTypingTimer: number | null = null;
let karinIdleTimer: number | null = null;

function typeKarinMessage(key: string) {
    if (!karinConsole) return;
    if (localStorage.getItem('karin_show_assistant') === 'false') return;
    const text = t(key);
    if (karinTypingTimer) window.clearInterval(karinTypingTimer);
    
    karinConsole.textContent = '';
    let i = 0;
    
    karinTypingTimer = window.setInterval(() => {
        karinConsole.textContent += text.charAt(i);
        i++;
        if (i >= text.length) {
            window.clearInterval(karinTypingTimer!);
            resetKarinIdleTimer();
        }
    }, 35);
}

function resetKarinIdleTimer() {
    if (karinIdleTimer) window.clearInterval(karinIdleTimer);
    karinIdleTimer = window.setInterval(() => {
        if (localStorage.getItem('karin_show_assistant') === 'false') return;
        const idleMessages = ['karin_idle_1', 'karin_idle_2', 'karin_idle_3', 'karin_idle_4', 'karin_idle_5', 'karin_idle_6', 'karin_idle_7', 'karin_idle_8', 'karin_idle_9', 'karin_idle_10', 'karin_idle_11', 'karin_idle_12', 'karin_idle_13', 'karin_idle_14', 'karin_idle_15', 'karin_idle_16', 'karin_idle_17', 'karin_idle_18', 'karin_idle_19', 'karin_idle_20'];
        const randomMsg = idleMessages[Math.floor(Math.random() * idleMessages.length)];
        typeKarinMessage(randomMsg);
    }, 25000); 
}

function applyKarinAssistantVisibility() {
    const consoleEl = document.querySelector('.karin-console') as HTMLElement | null;
    if (!consoleEl) return;
    const show = localStorage.getItem('karin_show_assistant') !== 'false';
    consoleEl.style.display = show ? '' : 'none';
}
applyKarinAssistantVisibility();

function initProfilesDrawer() {
    const trigger = document.getElementById('btn-open-profiles');
    const closeBtn = document.getElementById('btn-close-profiles');
    const drawer = document.getElementById('profiles-drawer');
    const overlay = document.getElementById('profiles-drawer-overlay');
    if (!trigger || !drawer || !overlay) return;

    const open = () => { drawer.classList.add('open'); overlay.classList.add('open'); };
    const close = () => { drawer.classList.remove('open'); overlay.classList.remove('open'); };

    trigger.addEventListener('click', open);
    closeBtn?.addEventListener('click', close);
    overlay.addEventListener('click', close);

    return { open, close };
}
const profilesDrawer = initProfilesDrawer();

function getLinkDisplayName(url: string): string {
    let displayName = "Proxy";
    try {
        const u = new URL(url);
        if (u.protocol === 'ovpn:') {
            const encodedName = u.searchParams.get('name');
            displayName = encodedName ? decodeURIComponent(encodedName).replace('.ovpn', '') : `OpenVPN (${u.hostname})`;
        } else if (u.protocol === 'wg:') {
            const encodedName = u.searchParams.get('name');
            displayName = encodedName ? decodeURIComponent(encodedName).replace('.conf', '') : `WireGuard (${u.hostname})`;
        } else {
            displayName = `${u.hostname}:${u.port || '443'}`;
            if (u.hash) displayName = decodeURIComponent(u.hash.substring(1)) + ` (${u.hostname})`;
        }
    } catch (e) {
        displayName = url.substring(0, 30) + '...';
    }
    return displayName;
}

function updateHeroProfileName() {
    const el = document.getElementById('hero-profile-name');
    if (!el) return;
    const target = activeLink || selectedProfileUrl;
    if (target) {
        el.textContent = getLinkDisplayName(target);
        el.removeAttribute('data-i18n');
    } else {
        el.setAttribute('data-i18n', 'hero_no_profile');
        el.textContent = t('hero_no_profile');
    }
    scheduleBridgeSync();
}

// **********************************
// МОСТИК ДЛЯ ВНЕШНИХ ОБОЛОЧЕК (karin-shell / Brain Shell)
// Снимок состояния уходит в Rust (он пишет shell.json), а команды из
// командной строки приходят событием `bridge-action` и превращаются в те же
// действия, что кнопки на главном экране.
// **********************************
interface BridgeAction { action: 'connect' | 'disconnect' | 'select'; url?: string | null; }

function selectProfile(url: string) {
    selectedProfileUrl = url;
    localStorage.setItem('karin_selected_profile', url);
    renderLinks();
    updateHeroProfileName();
}

function buildBridgeSnapshot() {
    const state = heroPhase === 'on' ? 'connected' : heroPhase === 'connecting' ? 'connecting' : 'disconnected';
    return {
        state,
        selectedUrl: selectedProfileUrl || '',
        ip: state === 'connected' ? bridgeIp : '',
        profiles: appLinks.map(l => ({
            url: l.url,
            name: getLinkDisplayName(l.url),
            group: appGroups.find(g => g.id === l.groupId)?.name || ''
        }))
    };
}

async function syncBridgeNow() {
    try {
        await invoke('bridge_update', { update: buildBridgeSnapshot() });
    } catch (e) {
        console.warn('bridge_update failed', e);
    }
}

function scheduleBridgeSync() {
    if (bridgeTimer !== null) window.clearTimeout(bridgeTimer);
    bridgeTimer = window.setTimeout(() => { bridgeTimer = null; void syncBridgeNow(); }, 150);
}

function handleBridgeAction(a: BridgeAction) {
    const url = a.url && appLinks.some(l => l.url === a.url) ? a.url : null;
    if (a.url && !url) return; // профиль уже удалён
    if (a.action === 'select') {
        if (url) selectProfile(url);
    } else if (a.action === 'disconnect') {
        // Во время подключения отключать нечего: как и в интерфейсе, кнопки «Отключить» тогда нет.
        if (heroPhase === 'on') disconnectProxy();
    } else if (a.action === 'connect') {
        if (heroPhase === 'connecting') return;
        if (url) selectProfile(url);
        if (heroPhase === 'on') {
            // Уже подключены: переподключаемся, только если попросили другой профиль.
            if (url && url !== activeLink) connectProxy(url);
        } else if (selectedProfileUrl) {
            connectProxy(selectedProfileUrl);
        } else {
            profilesDrawer?.open();
        }
    }
}

async function initBridge() {
    try {
        await listen<BridgeAction>('bridge-action', (event) => handleBridgeAction(event.payload));
    } catch (e) {
        console.warn('bridge-action listener failed', e);
    }
    await syncBridgeNow();
}

function initHeroCircle() {
    const circle = document.getElementById('hero-circle');
    circle?.addEventListener('click', () => {
        const isConnected = document.getElementById('status-text')?.className === 'status-active';
        if (isConnected) {
            disconnectProxy();
        } else if (selectedProfileUrl) {
            connectProxy(selectedProfileUrl);
        } else {
            profilesDrawer?.open();
        }
    });
}
initHeroCircle();

diagnostics = initDiagnostics({
    t,
    getLink: () => activeLink || selectedProfileUrl,
    isConnected: () => heroPhase === 'on',
    killSwitchOn: () => localStorage.getItem('karin_kill_switch') === 'true',
    goTo: (pageId: string) => switchPage(pageId),
    openProfiles: () => profilesDrawer?.open(),
    connect: () => {
        if (heroPhase === 'connecting' || heroPhase === 'on') return;
        if (selectedProfileUrl) connectProxy(selectedProfileUrl); else profilesDrawer?.open();
    },
    restartCore: () => {
        const link = activeLink || selectedProfileUrl;
        void (async () => {
            if (heroPhase === 'on') await disconnectProxy();
            if (link) connectProxy(link);
        })();
    },
    disableKillSwitch: () => {
        localStorage.setItem('karin_kill_switch', 'false');
        const toggle = document.getElementById('kill-switch-toggle') as HTMLInputElement | null;
        if (toggle) toggle.checked = false;
    },
});

// **********************************
// CORE PROXY & DNS LOGIC
// **********************************
function saveDnsState() {
    if(!domType || !domUrl || !domIp || !remType || !remUrl || !remIp) return;
    localStorage.setItem('karin_dns_dom', JSON.stringify({ type: domType.value, url: domUrl.value, ip: domIp.value }));
    localStorage.setItem('karin_dns_rem', JSON.stringify({ type: remType.value, url: remUrl.value, ip: remIp.value }));
}

function loadDnsState() {
    if(!domType || !domUrl || !domIp || !remType || !remUrl || !remIp) return;
    const d = safeParse('karin_dns_dom', {type:"doh", url:"https://dns.yandex.ru/dns-query", ip:"77.88.8.8"});
    const r = safeParse('karin_dns_rem', {type:"doh", url:"https://1.1.1.1/dns-query", ip:"1.1.1.1"});
    domType.value = d.type || "doh"; domUrl.value = d.url || ""; domIp.value = d.ip || "";
    remType.value = r.type || "doh"; remUrl.value = r.url || ""; remIp.value = r.ip || "";
}

[domType, domUrl, domIp, remType, remUrl, remIp].forEach(el => el?.addEventListener('change', saveDnsState));

// Applies a saved routing profile to the live routing/DNS state and persists it
function applyRouteProfile(p: RouteProfile) {
    if (!(domType && domUrl && domIp && remType && remUrl && remIp)) return;
    if (p.rules) routingState = JSON.parse(JSON.stringify(p.rules));
    if (p.defaultOutbound) defaultOutbound = p.defaultOutbound as ZoneKey;

    if (p.zonePriority) {
        zonePriority = [...p.zonePriority];
        localStorage.setItem('karin_zone_priority', JSON.stringify(zonePriority));
        applyColumnOrder();
    }

    domType.value = p.domDns?.type || 'doh';
    domUrl.value = p.domDns?.url || '';
    domIp.value = p.domDns?.ip || '';

    remType.value = p.remDns?.type || 'doh';
    remUrl.value = p.remDns?.url || '';
    remIp.value = p.remDns?.ip || '';

    saveDnsState();
    localStorage.setItem('karin_default_outbound', defaultOutbound);
    localStorage.setItem('karin_routing', JSON.stringify(routingState));
    updateDefaultOutboundUI();
    renderRouting();
}

// Turns routing delivered with a subscription into a dedicated profile (rules + default route).
// DNS is deliberately NOT taken from the subscription: those endpoints are tuned for mobile clients
// and break direct resolution here, so the profile keeps the DNS currently set in the UI.
// The profile is only saved, never applied automatically, so existing routing is not replaced.
function createProfileFromSubscription(result: SubscriptionResult, fallbackName: string) {
    if (!result.importedRouting) return;

    const rules: Record<ZoneKey, RoutingRule[]> = { direct: [], proxy: [], block: [] };
    if (result.importedRouting) {
        (Object.keys(rules) as ZoneKey[]).forEach(zone => {
            rules[zone] = result.importedRouting?.[zone] || [];
        });
    }

    const outbound: ZoneKey = (['direct', 'proxy', 'block'] as ZoneKey[]).includes(result.importedDefaultOutbound as ZoneKey)
        ? (result.importedDefaultOutbound as ZoneKey)
        : 'proxy';

    const name = (result.importedProfileName || fallbackName).trim();
    const profile: RouteProfile = {
        id: 'rp_' + Date.now(),
        name,
        defaultOutbound: outbound,
        rules,
        domDns: { type: domType?.value || 'doh', url: domUrl?.value ?? '', ip: domIp?.value ?? '' },
        remDns: { type: remType?.value || 'doh', url: remUrl?.value ?? '', ip: remIp?.value ?? '' },
        zonePriority: [...zonePriority]
    };

    // Re-importing the same subscription refreshes its profile instead of duplicating it
    const existing = routeProfiles.findIndex(x => x.name === name);
    if (existing >= 0) profile.id = routeProfiles[existing].id;
    if (existing >= 0) routeProfiles[existing] = profile; else routeProfiles.push(profile);

    localStorage.setItem('karin_route_profiles', JSON.stringify(routeProfiles));
    renderRoutingProfiles();
}

async function saveNewLink() {
    if(!linkInput) return;
    const input = linkInput.value.trim();
    if (!input) return;
    
    const addLink = (url: string, groupId: string | null = null) => {
        if (!appLinks.find(l => l.url === url)) {
            appLinks.push({ id: 'link_' + Date.now() + Math.random(), url, pinned: false, groupId });
        }
    };
  
    if (input.startsWith('vless://') || input.startsWith('vmess://') || input.startsWith('trojan://') || input.startsWith('ss://')) {
        addLink(input); 
        saveData(); 
        renderLinks(); 
        linkInput.value = ''; 
        typeKarinMessage('karin_add_link');
        return;
    }
    
    if (input.startsWith('http://') || input.startsWith('https://')) {
        if(!btnSave) return;
        const originalText = btnSave.innerText; 
        btnSave.innerText = t('btn_saving') || 'Загрузка...'; 
        btnSave.disabled = true;
        
        try {
            const result = await invoke<SubscriptionResult>('fetch_subscription', { url: input });
            const domain = new URL(input).hostname;
            const newGroupId = 'grp_' + Date.now();
            appGroups.push({ id: newGroupId, name: domain, pinned: false, isOpen: true });
            result.links.forEach(u => addLink(u, newGroupId));

            createProfileFromSubscription(result, domain);

            saveData();
            renderLinks();
            linkInput.value = '';
            typeKarinMessage('karin_add_link');
        } catch (error) { 
            alert(`Error: ${error}`); 
        } finally { 
            btnSave.innerText = originalText; 
            btnSave.disabled = false; 
        }
        return;
    }
    alert(t('err_invalid_link'));
}

async function connectProxy(link: string) {
    try {
        if(statusText) statusText.innerText = t('status_connecting');
        setHeroPhase('connecting');
        const dDns = safeParse('karin_dns_dom', {type:"doh", url:"https://dns.yandex.ru/dns-query", ip:"77.88.8.8"});
        const rDns = safeParse('karin_dns_rem', {type:"doh", url:"https://1.1.1.1/dns-query", ip:"1.1.1.1"});
    
        const result = await invoke('start_proxy', { 
            vlessLink: link, 
            routingState: routingState, 
            defaultOutbound: defaultOutbound,
            dnsParams: { domestic: dDns, remote: rDns },
            allowServerProxy: allowServerProxy,
            zonePriority: zonePriority,
            proxyLan: allowProxyLan,
            killSwitch: localStorage.getItem('karin_kill_switch') === 'true'
        });
        
        if (result === "OK") { 
            activeLink = link; 
            selectedProfileUrl = link;
            localStorage.setItem('karin_selected_profile', link);
            sessionStorage.setItem('karin_active_link', link); 
            updateStatusUI(); 
            renderLinks(); 
            typeKarinMessage('karin_connect_ok');
        } else {
            setHeroPhase(activeLink ? 'on' : 'idle');
        }
    } catch (error) { 
        setHeroPhase(activeLink ? 'on' : 'idle');
        alert(`Core Error: ${error}`); 
        if(statusText) statusText.innerText = t('status_inactive'); 
        typeKarinMessage('karin_connect_fail');
    }
}

async function disconnectProxy() { 
    await invoke('stop_proxy'); 
    activeLink = null; 
    sessionStorage.removeItem('karin_active_link'); 
    updateStatusUI(); 
    renderLinks(); 
    typeKarinMessage('karin_disconnect');
}

async function fetchLogs() {
    try {
        const logs = await invoke<string>('get_logs');
        if (logOutput) {
            const isScrolledToBottom = logOutput.scrollHeight - logOutput.clientHeight <= logOutput.scrollTop + 10;
            if (logs.trim() === "") {
                logOutput.textContent = t('logs_wait'); 
            } else {
                logOutput.textContent = logs;
            }
            if (isScrolledToBottom) logOutput.scrollTop = logOutput.scrollHeight;
        }
    } catch (err) { 
        console.error(err); 
    }
}

async function loadGeoCategories() { 
    try { 
        allAvailableTags = await invoke<string[]>('get_geosite_list'); 
    } catch (err) { 
        console.error(err); 
    } 
}

// **********************************
// UI RENDERING & HELPERS
// **********************************
function toggleMenu(show?: boolean) { 
    const isOpen = sidebar?.classList.contains('open'); 
    const shouldOpen = show !== undefined ? show : !isOpen; 
    sidebar?.classList.toggle('open', shouldOpen); 
    overlay?.classList.toggle('open', shouldOpen); 
}

function switchPage(pageId: string) { 
    closeZonePage();
    pages.forEach(page => page.classList.toggle('active', page.id === pageId)); 
    toggleMenu(false); 
    
    if (pageId === 'page-logs' && toggleLogs?.checked) { 
        fetchLogs(); 
        logInterval = window.setInterval(fetchLogs, 1500) as unknown as number; 
    } else { 
        if (logInterval) { clearInterval(logInterval); logInterval = null; } 
    } 
}

let heroTextTimer: number | null = null;
function typeHeroCoreText(newText: string) {
    const el = document.getElementById('hero-core-text');
    if (!el) return;
    if (heroTextTimer) window.clearInterval(heroTextTimer);
    const prefix = '[ ~$ ';
    const suffix = ' ]';
    let i = 0;
    heroTextTimer = window.setInterval(() => {
        el.textContent = prefix + newText.slice(0, i) + suffix;
        i++;
        if (i > newText.length) window.clearInterval(heroTextTimer!);
    }, 100);
}

// Состояние ядра на главном экране: покой / подключение / подключено.
// Сеть вращается всегда одной CSS-анимацией, а скорость плавно меняется
// через playbackRate: быстро при подключении, спокойно при подключении
// завершённом, до остановки при отключении. Так ничего не дёргается.
type HeroPhase = 'idle' | 'connecting' | 'on';
const HERO_SPIN_RATE: Record<HeroPhase, number> = { idle: 0, connecting: 6.5, on: 1 };
let heroPhase: HeroPhase = 'idle';
let heroSpinRate = 0;
let heroSpinFrame = 0;
let heroSpinInit = false;
let heroEchoTimer: number | null = null;

function rampHeroSpin(target: number) {
    const anim = document.querySelector('.hero-net')?.getAnimations()[0];
    if (!anim) return;
    if (!heroSpinInit) {
        heroSpinInit = true;
        anim.pause();
    }
    cancelAnimationFrame(heroSpinFrame);
    const from = heroSpinRate;
    const t0 = performance.now();
    const duration = 700;
    if (target > 0 && anim.playState === 'paused') anim.play();
    const step = (now: number) => {
        const k = Math.min(1, (now - t0) / duration);
        const eased = 1 - Math.pow(1 - k, 3);
        heroSpinRate = from + (target - from) * eased;
        anim.playbackRate = heroSpinRate;
        if (k < 1) {
            heroSpinFrame = requestAnimationFrame(step);
        } else if (target === 0) {
            anim.pause();
        }
    };
    heroSpinFrame = requestAnimationFrame(step);
}

function setHeroPhase(phase: HeroPhase) {
    const circle = document.getElementById('hero-circle');
    if (!circle) return;
    const prev = heroPhase;
    heroPhase = phase;
    circle.classList.toggle('connecting', phase === 'connecting');
    circle.classList.toggle('connected', phase === 'on');
    if (prev === 'on' && phase === 'idle') {
        circle.classList.add('disconnecting');
        if (heroEchoTimer) window.clearTimeout(heroEchoTimer);
        heroEchoTimer = window.setTimeout(() => circle.classList.remove('disconnecting'), 1000);
    }
    rampHeroSpin(HERO_SPIN_RATE[phase]);
    if (phase !== 'on') bridgeIp = '';
    scheduleBridgeSync();
}

function updateStatusUI() {
    const wasConnected = heroPhase === 'on';
    const nowConnected = !!activeLink;
    setHeroPhase(nowConnected ? 'on' : 'idle');
    if (wasConnected !== nowConnected) {
        typeHeroCoreText(nowConnected ? 'connect' : 'null');
    }
    updateHeroProfileName();
    if (activeLink) {
        if(statusText) { statusText.innerText = t('status_active'); statusText.className = "status-active"; }
        if(btnDisconnect) btnDisconnect.style.display = "block"; 
        if(btnPing) { btnPing.style.display = "block"; btnPing.innerText = t('btn_ping'); }
        if(statusIpBox) statusIpBox.style.display = "block"; 
        if(statusIp) statusIp.innerText = "...";
        invoke<string>('get_vpn_ip').then(ip => {
            if(statusIp) statusIp.innerText = ip;
            bridgeIp = ip.trim();
            scheduleBridgeSync();
        }).catch(() => {
            if(statusIp) statusIp.innerText = "Error";
            bridgeIp = '';
            scheduleBridgeSync();
        });
    } else {
        if(statusText) { statusText.innerText = t('status_inactive'); statusText.className = "status-inactive"; }
        if(btnDisconnect) btnDisconnect.style.display = "none"; 
        if(btnPing) btnPing.style.display = "none"; 
        if(statusIpBox) statusIpBox.style.display = "none";
    }
}

function updateDefaultOutboundUI() { 
    columns.forEach(col => { 
        const zone = col.dataset.zone; 
        if (zone === defaultOutbound) col.classList.add('active-default'); 
        else col.classList.remove('active-default'); 
    }); 
    
    if (defaultOutboundLabel) { 
        defaultOutboundLabel.innerText = defaultOutbound.charAt(0).toUpperCase() + defaultOutbound.slice(1); 
        if(defaultOutbound === 'direct') defaultOutboundLabel.style.color = 'var(--success)'; 
        if(defaultOutbound === 'proxy') defaultOutboundLabel.style.color = 'var(--accent)'; 
        if(defaultOutbound === 'block') defaultOutboundLabel.style.color = 'var(--danger)'; 
    } 
}

// Всё, что приходит извне (имена профилей и групп, ссылки, подписки, импортированные
// правила маршрутизации), вставляется в разметку только через esc() — иначе имя профиля
// вида `<img src=x onerror=...>` исполнялось бы в окне приложения, которое имеет доступ к IPC.
function esc(v: unknown): string {
    return String(v ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatProxyInfo(linkUrl: string): string {
    try {
        if (linkUrl.startsWith('vmess://')) { if (!linkUrl.includes('?')) return 'VMESS | Base64'; }
        const url = new URL(linkUrl); 
        const protocol = url.protocol.replace(':', '').toUpperCase();

        if (protocol === 'OVPN') {
            const proto = (url.searchParams.get('proto') || 'UDP').toUpperCase();
            const port = url.port || url.searchParams.get('port') || '1194';
            return `OpenVPN | ${proto} | ${port}`;
        }

        if (protocol === 'WG') {
            const ep = url.hostname;
            const port = url.port || '51820';
            return `WireGuard | UDP | ${ep}:${port}`;
        }

        const type = (url.searchParams.get('type') || 'TCP').toUpperCase();
        let security = url.searchParams.get('security') || 'NONE';
        if (security.toLowerCase() === 'tls') security = 'TLS'; 
        else if (security.toLowerCase() === 'reality') security = 'Reality'; 
        else security = security.toUpperCase();
        return `${protocol} | ${type} | ${security}`;
    } catch (e) { 
        return "Unknown Format"; 
    }
}

function showPrompt(title: string, defaultValue = ''): Promise<string | null> {
    return new Promise((resolve) => {
        const modal = document.getElementById('prompt-modal') as HTMLDialogElement;
        const input = document.getElementById('prompt-input') as HTMLInputElement;
        const btnOk = document.getElementById('prompt-ok') as HTMLButtonElement;
        const btnCancel = document.getElementById('prompt-cancel') as HTMLButtonElement;
        const titleEl = document.getElementById('prompt-title') as HTMLHeadingElement;

        titleEl.textContent = title; 
        input.value = defaultValue; 
        modal.showModal(); 
        input.focus();

        const cleanup = () => {
            btnOk.removeEventListener('click', onOk); 
            btnCancel.removeEventListener('click', onCancel);
            modal.removeEventListener('cancel', onCancel); 
            input.removeEventListener('keydown', onKey);
        };
        const onOk = () => { cleanup(); modal.close(); resolve(input.value.trim()); };
        const onCancel = () => { cleanup(); modal.close(); resolve(null); };
        const onKey = (e: KeyboardEvent) => { if (e.key === 'Enter') onOk(); };

        btnOk.addEventListener('click', onOk); 
        btnCancel.addEventListener('click', onCancel);
        modal.addEventListener('cancel', onCancel); 
        input.addEventListener('keydown', onKey);
    });
}

function renderLinkItem(item: ProxyLink) {
    const isCurrentActive = activeLink === item.url;
    const isSelected = !isCurrentActive && selectedProfileUrl === item.url;
    let displayName = "Proxy";
    try {
        const url = new URL(item.url); 
        if (url.protocol === 'ovpn:') {
            const encodedName = url.searchParams.get('name');
            if (encodedName) {
                displayName = decodeURIComponent(encodedName).replace('.ovpn', '');
            } else {
                displayName = `OpenVPN (${url.hostname})`;
            }
        } else if (url.protocol === 'wg:') {
            const encodedName = url.searchParams.get('name');
            if (encodedName) {
                displayName = decodeURIComponent(encodedName).replace('.conf', '');
            } else {
                displayName = `WireGuard (${url.hostname})`;
            }
        } else {
            displayName = `${url.hostname}:${url.port || '443'}`;
            if (url.hash) displayName = decodeURIComponent(url.hash.substring(1)) + ` (${url.hostname})`;
        }
    }   catch (e) { 
            displayName = item.url.substring(0, 30) + '...'; 
    }

    const formattedProtocol = formatProxyInfo(item.url);
    const pinIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 6px;"><path d="M12 17v5"/><path d="M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z"/></svg>`;
    const checkboxHtml = isEditMode ? `<input type="checkbox" class="edit-checkbox" data-id="${esc(item.id)}" ${selectedLinks.has(item.id) ? 'checked' : ''}>` : '';
    const actionsHtml = isEditMode ? '' : `
        <button class="btn-menu-dots" data-index="${esc(item.id)}">⋮</button>
        <div class="dropdown-menu" id="menu-${esc(item.id)}" style="display:none;">
          <button class="btn-share" data-url="${esc(item.url)}">${t('btn_share')}</button>
          <button class="btn-pin" data-id="${esc(item.id)}">${item.pinned ? t('btn_unpin') : t('btn_pin')}</button>
          <button class="btn-delete-link danger" style="background: transparent; color: var(--danger);" data-id="${esc(item.id)}">${t('btn_delete')}</button>
        </div>
    `;

    return `
      <div class="link-item ${isSelected ? 'link-item-selected' : ''}" data-select-url="${esc(item.url)}" style="${isEditMode ? '' : 'cursor: pointer;'}">
        ${checkboxHtml}
        <div class="link-info">
          <div class="link-name" style="font-size: 14.5px; display: flex; align-items: center; ${isCurrentActive ? 'color: var(--success); font-weight: bold;' : 'font-weight: 500;'}">
            ${item.pinned && !item.groupId ? pinIcon : ''}${esc(displayName)}
          </div>
          <div class="link-url" style="font-size: 12px; color: var(--text-dim); opacity: 0.95; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; letter-spacing: 0.3px;">
            ${esc(formattedProtocol)}
          </div>
        </div>
        ${pingChipHtml(item.url)}
        <div class="link-actions">${actionsHtml}</div>
      </div>
    `;
}

// **********************************
// PING OF ALL SERVERS
// Время TCP-соединения с портом сервера (как шаг «Порт сервера» в диагностике).
// Пока VPN включён, замер идёт через туннель, поэтому такие значения приглушены.
// **********************************
type PingResult =
    | { state: 'pending' }
    | { state: 'na' }
    | { state: 'fail' }
    | { state: 'ok'; ms: number; viaTunnel: boolean };

const PING_GOOD_MS = 250;
const PING_MID_MS = 500;
const PING_CONCURRENCY = 6;
const serverPings = new Map<string, PingResult>();
let pingInFlight = false;

function pingChipHtml(url: string): string {
    const result = serverPings.get(url);
    if (!result) return '';
    if (result.state === 'pending') return '<span class="ping-chip none">…</span>';
    if (result.state === 'na') return '<span class="ping-chip none">—</span>';
    if (result.state === 'fail') return `<span class="ping-chip none">${esc(t('ping_no_answer'))}</span>`;
    const level = result.ms <= PING_GOOD_MS ? 'good' : result.ms <= PING_MID_MS ? 'mid' : 'bad';
    const text = t('diag_ms').replace('{ms}', String(result.ms));
    return `<span class="ping-chip ${level}${result.viaTunnel ? ' dim' : ''}">${esc(text)}</span>`;
}

function paintPing(url: string) {
    document.querySelectorAll<HTMLElement>('.link-item').forEach(item => {
        if (item.dataset.selectUrl !== url) return;
        item.querySelector('.ping-chip')?.remove();
        const html = pingChipHtml(url);
        if (html) item.querySelector('.link-actions')?.insertAdjacentHTML('beforebegin', html);
    });
}

async function pingServer(url: string, viaTunnel: boolean): Promise<PingResult> {
    const endpoint = extractEndpoint(url);
    if (!endpoint || endpoint.transport !== 'tcp') return { state: 'na' };
    try {
        const raw = await invoke<string>('diag_tcp', { host: endpoint.host, port: endpoint.port });
        if (raw.startsWith('open:')) return { state: 'ok', ms: Math.max(1, Number(raw.slice(5)) || 1), viaTunnel };
        return { state: 'fail' };
    } catch {
        return { state: 'fail' };
    }
}

async function pingAllServers() {
    if (pingInFlight || appLinks.length === 0) return;
    pingInFlight = true;
    const button = document.getElementById('btn-ping-all') as HTMLButtonElement | null;
    const label = document.getElementById('btn-ping-label');
    const hint = document.getElementById('ping-hint');
    const viaTunnel = heroPhase === 'on';
    if (button) button.disabled = true;
    if (label) label.textContent = t('ping_running');
    if (hint) hint.hidden = true;

    const urls = Array.from(new Set(appLinks.map(link => link.url)));
    urls.forEach(url => serverPings.set(url, { state: 'pending' }));
    renderLinks();

    try {
        let next = 0;
        const worker = async () => {
            while (next < urls.length) {
                const url = urls[next++];
                serverPings.set(url, await pingServer(url, viaTunnel));
                paintPing(url);
            }
        };
        await Promise.all(Array.from({ length: Math.min(PING_CONCURRENCY, urls.length) }, worker));
    } finally {
        pingInFlight = false;
        if (button) button.disabled = false;
        if (label) label.textContent = t('ping_btn');
        if (hint) hint.hidden = !viaTunnel;
    }
}

function renderLinks() {
    const countEl = document.getElementById('links-count');
    if (countEl) countEl.textContent = appLinks.length > 0 ? String(appLinks.length) : '';
    document.querySelector<HTMLElement>('.drawer-section-label')?.classList.toggle('is-empty', appLinks.length === 0);
    btnEditMode?.classList.toggle('is-active', isEditMode);
    if(!linksContainer) return;
    linksContainer.innerHTML = '';
    
    if (appLinks.length === 0) { 
     linksContainer.innerHTML = `
       <div class="empty-state">
           <img src="/karin-empty.png" alt="Karin" class="empty-state-img">
           <div class="empty-state-text">
               ${t('empty_state_text')}
           </div>
       </div>`; 
     return; 
    }
  
    const pinnedGroups = appGroups.filter(g => g.pinned);
    const unpinnedGroups = appGroups.filter(g => !g.pinned);
    
    const renderGroup = (g: ProxyGroup) => {
        const gLinks = appLinks.filter(l => l.groupId === g.id);
        if (gLinks.length === 0) return ''; 
        const pinIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 6px;"><path d="M12 17v5"/><path d="M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z"/></svg>`;
        
        let html = `
          <div class="group-header" data-id="${esc(g.id)}">
              <div style="display: flex; align-items: center; gap: 8px;">
                  ${isEditMode ? `<input type="checkbox" class="edit-checkbox" data-group-id="${esc(g.id)}" ${selectedGroups.has(g.id) ? 'checked' : ''}>` : ''}
                  ${g.pinned ? pinIcon : ''} <span>${esc(g.name)}</span> <span style="font-size:12px; color:var(--text-dim);">(${gLinks.length})</span>
              </div>
              <div style="display:flex; gap:10px;">
                  <span style="color:var(--text-dim); transition: transform 0.2s; transform: ${g.isOpen ? 'rotate(180deg)' : 'rotate(0deg)'};">▼</span>
              </div>
          </div>
        `;
        if (g.isOpen) {
            html += `<div class="group-content">` + gLinks.map(l => renderLinkItem(l)).join('') + `</div>`;
        }
        return html;
    };
  
    let html = '';
    pinnedGroups.forEach(g => html += renderGroup(g));
    appLinks.filter(l => l.groupId === null && l.pinned).forEach(l => html += renderLinkItem(l));
    unpinnedGroups.forEach(g => html += renderGroup(g));
    appLinks.filter(l => l.groupId === null && !l.pinned).forEach(l => html += renderLinkItem(l));
  
    linksContainer.innerHTML = html;
    
    document.querySelectorAll('.edit-checkbox[data-group-id]').forEach(cb => {
        // раньше было inline-атрибутом onclick="event.stopPropagation()" — CSP такое запрещает
        cb.addEventListener('click', (e) => e.stopPropagation());
        cb.addEventListener('change', (e) => {
            const gId = (e.target as HTMLInputElement).dataset.groupId!;
            const isChecked = (e.target as HTMLInputElement).checked;
            
            if (isChecked) selectedGroups.add(gId); else selectedGroups.delete(gId);
            
            appLinks.filter(l => l.groupId === gId).forEach(l => {
                if (isChecked) selectedLinks.add(l.id); else selectedLinks.delete(l.id);
            });
            renderLinks();
        });
    });
}

function renderRouting() { 
    Object.keys(zones).forEach(key => { 
        const zone = zones[key as keyof typeof zones]; 
        if(zone) { 
            zone.textContent = '';
            const addBtn = document.createElement('button');
            addBtn.className = 'btn-add';
            addBtn.dataset.zone = key;
            addBtn.textContent = '+';
            zone.appendChild(addBtn);
            if (routingState[key as ZoneKey]) {
                routingState[key as ZoneKey].forEach((rule: any) => { 
                    const el = document.createElement('div'); 
                    el.className = 'tag-item'; 
                    el.appendChild(document.createTextNode(`${rule.value} `));
                    const del = document.createElement('span');
                    del.className = 'btn-delete-tag';
                    del.dataset.tag = String(rule.value);
                    del.dataset.zone = key;
                    del.style.pointerEvents = 'auto';
                    del.textContent = '×';
                    el.appendChild(del);
                    zone.appendChild(el); 
                }); 
            }
        }
    }); 
    localStorage.setItem('karin_routing', JSON.stringify(routingState)); 
    renderZoneCards();
    if (openZone) renderZoneSubpage();
    updateRoutingProfileName();
}

// **********************************
// ROUTING: ZONE CARDS AND ZONE PAGE
// Три карточки слева направо в порядке приоритета. Клик по карточке открывает страницу зоны
// (правила, маршрут по умолчанию, порядок). Колонки #routing-grid остаются в DOM скрытыми:
// они хранят состояние правил, как и раньше.
// **********************************
const ZONE_META: Record<ZoneKey, { label: string, color: string, descKey: string, icon: string }> = {
    direct: {
        label: 'Direct', color: 'var(--success)', descKey: 'zone_desc_direct',
        icon: '<path d="M5 12h14"/><path d="m13 6 6 6-6 6"/>'
    },
    proxy: {
        label: 'Proxy', color: 'var(--accent)', descKey: 'zone_desc_proxy',
        icon: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
    },
    block: {
        label: 'Block', color: 'var(--danger)', descKey: 'zone_desc_block',
        icon: '<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>'
    },
};

function svgIcon(path: string, size = 20): string {
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${path}</svg>`;
}

function renderZoneCards() {
    const host = document.getElementById('zone-cards');
    if (!host) return;
    host.replaceChildren();
    zonePriority.forEach((zone, index) => {
        const meta = ZONE_META[zone];
        const count = routingState[zone]?.length || 0;
        const card = document.createElement('button');
        card.type = 'button';
        card.className = `zone-card${zone === defaultOutbound ? ' is-default' : ''}`;
        card.dataset.zoneOpen = zone;
        card.style.setProperty('--zone-color', meta.color);
        card.innerHTML = `
            <span class="zone-card-top">
                <span class="zone-card-icon">${svgIcon(meta.icon, 22)}</span>
                <span class="zone-card-chevron">${svgIcon('<path d="m9 6 6 6-6 6"/>', 18)}</span>
            </span>
            <span class="zone-card-title">${esc(meta.label)}${zone === defaultOutbound ? `<span class="zone-badge">${esc(t('zone_default_badge'))}</span>` : ''}</span>
            <span class="zone-card-desc">${esc(t(meta.descKey))}</span>
            <span class="zone-card-meta">${esc(count > 0 ? t('zone_rules_count').replace('{n}', String(count)) : t('zone_no_rules'))}</span>
        `;
        host.appendChild(card);
        if (index < zonePriority.length - 1) {
            const arrow = document.createElement('div');
            arrow.className = 'zone-arrow';
            arrow.setAttribute('aria-hidden', 'true');
            arrow.innerHTML = svgIcon('<path d="M5 12h14"/><path d="m13 6 6 6-6 6"/>', 18);
            host.appendChild(arrow);
        }
    });
}

function renderZoneSubpage() {
    const host = document.getElementById('subpage-zone');
    if (!host || !openZone) return;
    const zone = openZone;
    const meta = ZONE_META[zone];
    const rules: any[] = routingState[zone] || [];
    const position = zonePriority.indexOf(zone);

    const rulesHtml = rules.length === 0
        ? `<div class="zone-empty">${esc(t('zone_empty'))}</div>`
        : rules.map(rule => `
            <div class="tag-item zone-rule">
                <span class="zone-rule-text">${esc(String(rule.value))}</span>
                <span class="btn-delete-tag" data-tag="${esc(String(rule.value))}" data-zone="${zone}" role="button" aria-label="${esc(t('btn_delete'))}">×</span>
            </div>`).join('');

    host.style.setProperty('--zone-color', meta.color);
    host.innerHTML = `
        <div class="subpage-header">
            <button type="button" class="subpage-back" data-subpage-close aria-label="${esc(t('nav_back'))}">${svgIcon('<path d="m15 18-6-6 6-6"/>', 20)}</button>
            <div class="subpage-title zone-title"><span class="zone-title-icon">${svgIcon(meta.icon, 20)}</span>${esc(meta.label)}</div>
        </div>
        <div class="subpage-body">
            <p class="subpage-lead">${esc(t(meta.descKey))}</p>
            <div class="zone-settings">
                <div class="zone-setting">
                    <div class="zone-setting-copy">
                        <div class="zone-setting-title">${esc(t('zone_default_title'))}</div>
                        <div class="zone-setting-hint">${esc(t('zone_default_hint'))}</div>
                    </div>
                    ${zone === defaultOutbound
                        ? `<span class="zone-badge zone-badge-solid">${esc(t('zone_default_badge'))}</span>`
                        : `<button type="button" class="outline-btn" data-zone-default="${zone}">${esc(t('zone_make_default'))}</button>`}
                </div>
                <div class="zone-setting">
                    <div class="zone-setting-copy">
                        <div class="zone-setting-title">${esc(t('zone_priority').replace('{n}', String(position + 1)).replace('{total}', String(zonePriority.length)))}</div>
                        <div class="zone-setting-hint">${esc(t('zone_priority_hint'))}</div>
                    </div>
                    <div class="zone-move">
                        <button type="button" class="outline-btn icon-only" data-zone-move="-1" aria-label="${esc(t('zone_move_left'))}" title="${esc(t('zone_move_left'))}" ${position <= 0 ? 'disabled' : ''}>${svgIcon('<path d="m15 18-6-6 6-6"/>', 18)}</button>
                        <button type="button" class="outline-btn icon-only" data-zone-move="1" aria-label="${esc(t('zone_move_right'))}" title="${esc(t('zone_move_right'))}" ${position >= zonePriority.length - 1 ? 'disabled' : ''}>${svgIcon('<path d="m9 18 6-6-6-6"/>', 18)}</button>
                    </div>
                </div>
            </div>
            <h4 class="subpage-section-title">${esc(t('zone_rules_title'))}</h4>
            <div class="zone-rules">${rulesHtml}</div>
            <button type="button" class="btn-add" data-zone="${zone}">${esc(t('zone_add_rule'))}</button>
        </div>
    `;
}

function openZonePage(zone: ZoneKey) {
    openZone = zone;
    renderZoneSubpage();
    const el = document.getElementById('subpage-zone');
    if (!el) return;
    el.classList.add('open');
    el.setAttribute('aria-hidden', 'false');
    const body = el.querySelector<HTMLElement>('.subpage-body');
    if (body) body.scrollTop = 0;
}

function closeZonePage(): boolean {
    const el = document.getElementById('subpage-zone');
    if (!el || !el.classList.contains('open')) return false;
    el.classList.remove('open');
    el.setAttribute('aria-hidden', 'true');
    openZone = null;
    return true;
}

function setActiveRouteProfile(id: string | null) {
    activeRouteProfileId = id;
    try {
        if (id) localStorage.setItem('karin_active_route_profile', id);
        else localStorage.removeItem('karin_active_route_profile');
    } catch { /* storage unavailable */ }
    updateRoutingProfileName();
}

/** Name of the routing profile (rules + DNS preset) that was last applied or saved. */
function updateRoutingProfileName() {
    const el = document.getElementById('routing-profile-name');
    if (!el) return;
    const profile = activeRouteProfileId ? routeProfiles.find(p => p.id === activeRouteProfileId) : undefined;
    if (activeRouteProfileId && !profile) {
        activeRouteProfileId = null;
        try { localStorage.removeItem('karin_active_route_profile'); } catch { /* ignore */ }
    }
    if (profile) {
        el.textContent = profile.name;
        el.removeAttribute('data-i18n');
    } else {
        el.setAttribute('data-i18n', 'routing_profile_none');
        el.textContent = t('routing_profile_none');
    }
}

// Перетаскивание карточек зон мышью (по горизонтали). Короткий клик без движения открывает зону.
let suppressZoneClickUntil = 0;

function initZoneCardDragAndDrop() {
    const host = document.getElementById('zone-cards');
    if (!host) return;

    const MOVE_THRESHOLD = 6;
    let card: HTMLElement | null = null;
    let pointerId: number | null = null;
    let startX = 0, grabOffset = 0;
    let dragging = false;

    const cards = () => Array.from(host.querySelectorAll<HTMLElement>('.zone-card'));

    const beginDrag = () => {
        if (!card) return;
        dragging = true;
        host.classList.add('is-sorting');
        host.querySelectorAll('.zone-arrow').forEach(el => el.remove());
        card.classList.add('is-dragging');
        grabOffset = startX - card.getBoundingClientRect().left;
        try { card.setPointerCapture(pointerId as number); } catch { /* ignore */ }
    };

    const moveDrag = (clientX: number) => {
        if (!card) return;
        let before: HTMLElement | null = null;
        for (const other of cards().filter(el => el !== card)) {
            const r = other.getBoundingClientRect();
            if (clientX < r.left + r.width / 2) { before = other; break; }
        }
        if (before !== (card.nextElementSibling as HTMLElement | null)) host.insertBefore(card, before);
        card.style.transform = 'none';
        const hostRect = host.getBoundingClientRect();
        const cardRect = card.getBoundingClientRect();
        const wanted = Math.min(Math.max(clientX - grabOffset, hostRect.left), hostRect.right - cardRect.width);
        card.style.transform = `translateX(${wanted - cardRect.left}px)`;
    };

    const finish = (commit: boolean) => {
        const wasDragging = dragging;
        const dragged = card;
        if (wasDragging && dragged) {
            suppressZoneClickUntil = Date.now() + 300;
            if (commit) {
                const order = cards().map(el => el.dataset.zoneOpen as ZoneKey);
                if (order.length === zonePriority.length && order.every(z => zonePriority.includes(z))) {
                    zonePriority = order;
                    localStorage.setItem('karin_zone_priority', JSON.stringify(zonePriority));
                    applyColumnOrder();
                }
            }
            dragged.style.transform = '';
            dragged.classList.remove('is-dragging');
        }
        host.classList.remove('is-sorting');
        dragging = false;
        card = null;
        pointerId = null;
        if (wasDragging) renderRouting();
    };

    host.addEventListener('pointerdown', (e) => {
        if (e.pointerType === 'mouse' && e.button !== 0) return;
        const target = (e.target as HTMLElement).closest<HTMLElement>('.zone-card');
        if (!target) return;
        card = target;
        pointerId = e.pointerId;
        startX = e.clientX;
    });

    host.addEventListener('pointermove', (e) => {
        if (card === null || e.pointerId !== pointerId) return;
        if (!dragging) {
            if (Math.abs(e.clientX - startX) > MOVE_THRESHOLD) beginDrag();
            else return;
        }
        e.preventDefault();
        moveDrag(e.clientX);
    });

    host.addEventListener('pointerup', (e) => { if (e.pointerId === pointerId) finish(true); });
    host.addEventListener('pointercancel', (e) => { if (e.pointerId === pointerId) finish(false); });
}

function renderRoutingProfiles() {
    const list = document.getElementById('routing-profiles-list');
    if (!list) return;
    list.innerHTML = '';
    let profilesHtml = '';
    routeProfiles.forEach(p => {
        profilesHtml += `
            <div class="profile-item">
                <span>${esc(p.name)}</span>
                <div class="link-actions">
                    <button class="secondary btn-load-profile" data-id="${esc(p.id)}" style="padding: 6px 12px; font-size: 13px;">${t('btn_select')}</button>
                    <button class="btn-menu-dots btn-route-menu-dots" data-index="${esc(p.id)}">⋮</button>
                    <div class="dropdown-menu" id="route-menu-${esc(p.id)}" style="display:none;">
                        <button class="btn-edit-profile" data-id="${esc(p.id)}">${t('btn_rename')}</button>
                        <button class="btn-export-profile" data-id="${esc(p.id)}">${t('btn_share')}</button>
                        <button class="btn-del-profile danger" style="background: transparent; color: var(--danger);" data-id="${esc(p.id)}">${t('btn_delete')}</button>
                    </div>
                </div>
            </div>
        `;
    });
    list.innerHTML = profilesHtml;
    updateRoutingProfileName();
}

function renderAboutPage() {
    const infoPanel = document.getElementById('about-info-panel');
    const patchPanel = document.getElementById('about-patch-panel');

    if (infoPanel) {
        infoPanel.innerHTML = `
            <div style="display: flex; gap: 20px; align-items: center; margin-bottom: 20px; padding-bottom: 20px; border-bottom: 1px solid var(--border-color); flex-shrink: 0;">
                <img src="/karin-about.png" alt="KarinCore" style="width: 90px; height: 90px; border-radius: 16px; object-fit: cover; border: 2px solid var(--accent); box-shadow: 0 0 15px rgba(203, 166, 247, 0.15);">
                <div>
                    <h2 style="margin: 0; color: var(--accent); font-weight: 600; font-size: 26px; letter-spacing: 0.5px;">KarinCore</h2>
                    <div style="font-size: 13px; color: var(--success); margin-top: 4px; font-family: monospace;">${t('about_version')}</div>
                </div>
            </div>
            
            <div class="tab-scroll-content" style="font-size: 14px; line-height: 1.6; color: var(--text-color); display: flex; flex-direction: column; gap: 16px; padding-bottom: 30px;">
                <p style="margin: 0; text-align: justify;">${t('about_p1')}</p>
                
                <div>
                    <h4 style="margin: 0 0 2px 0; color: var(--accent); font-size: 15px; font-weight: 600;">${t('about_manifest_title')}</h4>
                    <p style="margin: 0; text-align: justify;">${t('about_manifest_p1')}</p>
                </div>
                
                <div>
                    <h4 style="margin: 0 0 2px 0; color: var(--accent); font-size: 15px; font-weight: 600;">${t('about_roadmap_title')}</h4>
                    <p style="margin: 0; padding-left: 10px; border-left: 2px solid var(--border-color); text-align: justify;">${t('about_roadmap_p1')}</p>
                </div>
                
                <div>
                    <h4 style="margin: 0 0 2px 0; color: var(--accent); font-size: 15px; font-weight: 600;">${t('about_support_title')}</h4>
                    <p style="margin: 0; text-align: justify;">${t('about_support_p1')}</p>
                </div>
                
                <div style="background: var(--base-crust); border: 1px solid var(--border-color); padding: 12px; border-radius: 8px; font-family: monospace; font-size: 13px; display: flex; flex-direction: column; gap: 4px; flex-shrink: 0;">
                    <div><span style="color: var(--accent);">• ${t('about_author')}:</span> detestern</div>
                    <div><span style="color: var(--accent);">• GitHub:</span> <span class="copyable-item" data-copy="https://github.com/detestern/KarinCore" style="color: var(--text-color);">https://github.com/detestern/KarinCore</span></div>
                    <div><span style="color: var(--accent);">• ${t('about_contact')}:</span> <span class="copyable-item" data-copy="detestern@proton.me" style="color: var(--text-color);">detestern@proton.me</span></div>
                    <div><span style="color: var(--accent);">• Crypto (USDT TRC20):</span> <span class="copyable-item" data-copy="TQCQhGQD6xgaDxwqAVcTiapS6rdcPyf24X" style="color: var(--success);">[TQCQhGQD6xgaDxwqAVcTiapS6rdcPyf24X]</span></div>
                </div>
                
                <div style="margin-top: 4px; background: var(--base-crust); border: 1px solid var(--border-color); padding: 14px; border-radius: 8px; flex-shrink: 0; position: relative; overflow: hidden;">
                    <div style="position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: var(--success);"></div>
                    <h4 style="margin: 0 0 10px 0; color: var(--success); font-size: 14px; font-weight: 600; display: flex; align-items: center; gap: 8px; text-transform: uppercase; letter-spacing: 0.5px;">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        ${t('about_legal_title')}
                    </h4>
                    <div style="font-size: 13px; color: var(--text-color); line-height: 1.6; text-align: justify; font-family: monospace;">
                        <span style="color: var(--accent);">[COPYRIGHT]</span> ${t('about_legal_copyright')}<br><br>
                        <span style="color: var(--accent);">[ZERO TELEMETRY]</span> ${t('about_legal_privacy')}
                    </div>
                </div>
            </div>
        `;

        const copyItems = infoPanel.querySelectorAll('.copyable-item');
        copyItems.forEach(item => {
            item.addEventListener('click', async (e) => {
                const target = e.target as HTMLElement;
                const textToCopy = target.getAttribute('data-copy');
                
                if (textToCopy) {
                    try {
                        await navigator.clipboard.writeText(textToCopy);
                        
                        const originalText = target.innerText;
                        const originalColor = target.style.color;
                        
                        target.innerText = t('btn_copied');
                        target.style.color = 'var(--accent)';
                        
                        setTimeout(() => {
                            target.innerText = originalText;
                            target.style.color = originalColor;
                        }, 1500);
                    } catch (err) {
                        console.error(err);
                    }
                }
            });
        });
    }

    if (patchPanel) {
        patchPanel.innerHTML = `
            <h3 style="margin-top: 0; margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid var(--border-color); display: flex; align-items: center; gap: 8px; flex-shrink: 0;">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
                ${t('patch_notes')}
            </h3>
            
            <div class="patch-scroll-area" style="overflow-y: auto; flex: 1; padding-right: 10px; font-size: 13px; color: var(--text-dim); line-height: 1.6; white-space: pre-wrap; padding-bottom: 30px;">${t('about_text_2')}</div>
        `;
    }
}

function renderSearchResults(tags: string[]) { 
    if(!searchResults || !modalSearch) return; 
    searchResults.innerHTML = ''; 
    tags.slice(0, 10).forEach(tag => { 
        const el = document.createElement('div'); 
        el.className = 'tag-item'; 
        el.innerText = tag; 
        el.onclick = () => { 
            addRule(tag, 'geosite'); 
            searchModal?.close(); 
            modalSearch.value = ''; 
        }; 
        searchResults.appendChild(el); 
    }); 
}

function handleManualAdd() { 
    if(!manualInput) return; 
    let val = manualInput.value.trim().toLowerCase(); 
    if (!val) return; 
    
    const ipRegex = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(3[0-2]|[1-2]?[0-9]))?$/; 
    const domainRegex = /^(domain:|full:|keyword:|regexp:)?([a-zA-Z0-9\-\.\_\*]+)$/; 
    let type = ''; 
    
    if (ipRegex.test(val)) type = 'ip'; 
    else if (domainRegex.test(val)) type = 'domain'; 
    else { alert(t('err_invalid_rule')); return; } 
    
    addRule(val, type); 
    manualInput.value = ''; 
}

function addRule(value: string, type: string) { 
    routingState[currentZone as ZoneKey].push({ type, value }); 
    renderRouting(); 
    searchModal?.close(); 
}

// **********************************
// APPLICATION UPDATE CHECKER
// **********************************
async function checkApplicationUpdates() {
    const statusEl = document.getElementById('update-status');
    if (!statusEl) return;

    try {
        const CURRENT_VERSION = "1.5.4";

        const response = await fetch("https://api.github.com/repos/detestern/KarinCore/releases/latest");
        if (!response.ok) return;

        const data = await response.json();
        const latestVersion = data.tag_name.replace('v', '').trim();

        if (latestVersion === CURRENT_VERSION) {
            statusEl.innerHTML = `<span style="opacity: 0.6;">${t('update_current')}</span>`;
        } else {
            statusEl.innerHTML = `
                <a class="update-link" href="https://github.com/detestern/KarinCore/releases/latest" target="_blank">
                    ${t('update_available')}
                    <span class="notification-dot"></span>
                </a>
            `;

            const link = statusEl.querySelector('.update-link');
            link?.addEventListener('click', (e) => {
                e.preventDefault();
                invoke('open_browser', { url: "https://github.com/detestern/KarinCore/releases/latest" })
                    .catch(console.error);
            });
        }
    } catch (err) {
        console.error("Update check failed:", err);
    }
}

// **********************************
// INITIALIZATION & EVENT LISTENERS
// **********************************
function init() {
    // Кнопки закрытия диалогов (раньше — inline onclick, запрещённый CSP).
    document.querySelectorAll<HTMLElement>('[data-close-modal]').forEach(btn => {
        btn.addEventListener('click', () => {
            (document.getElementById(btn.dataset.closeModal || '') as HTMLDialogElement | null)?.close();
        });
    });
    document.getElementById('titlebar-minimize')?.addEventListener('click', () => invoke('minimize_window'));
    document.getElementById('titlebar-maximize')?.addEventListener('click', () => invoke('maximize_window'));
    document.getElementById('titlebar-close')?.addEventListener('click', () => invoke('close_window'));

    setTimeout(() => {
        const splash = document.getElementById('splash-screen');
        if (splash) {
            splash.style.opacity = '0';
            setTimeout(() => {
                splash.style.visibility = 'hidden';
                typeKarinMessage('karin_greet');
            }, 500);
        }
    }, 1500);  

    updateUIStrings();
    if (langLabel) langLabel.textContent = langNames[currentLang] || "English";
    
    // Инициализация Drag and Drop для колонок маршрутизации
    initDragAndDrop();
    initZoneCardDragAndDrop();
    applyColumnOrder();

    renderLinks(); 
    updateStatusUI(); 
    updateDefaultOutboundUI(); 
    renderRouting(); 
    loadGeoCategories(); 
    renderAboutPage();
    loadDnsState(); 
    renderRoutingProfiles();
    
    if (currentTheme === 'light') {
        document.documentElement.setAttribute('data-theme', 'light');
        if (themeToggle) themeToggle.checked = true;
        if (themeLabel) {
            themeLabel.setAttribute('data-i18n', 'theme_light');
            themeLabel.textContent = t('theme_light');
        }
    } else {
        if (themeLabel) {
            themeLabel.setAttribute('data-i18n', 'theme_dark');
            themeLabel.textContent = t('theme_dark');
        }
    }
    
    langBtn?.addEventListener('click', () => {
        if (langMenu) {
            const isO = langMenu.style.display === 'flex';
            document.querySelectorAll('.dropdown-menu').forEach(m => (m as HTMLElement).style.display = 'none');
            langMenu.style.display = isO ? 'none' : 'flex';
        }
    });

    document.querySelectorAll('.lang-option').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const target = e.target as HTMLButtonElement;
            currentLang = target.dataset.value!;
            if (langLabel) langLabel.textContent = target.textContent;
            if (langMenu) langMenu.style.display = 'none';
            
            localStorage.setItem('karin_lang', currentLang);
            updateUIStrings(); 
            renderLinks(); 
            updateStatusUI(); 
            renderAboutPage();
            renderRoutingProfiles();
            renderRouting();
            checkApplicationUpdates();
        });
    });

    if (toggleServerProxy) {
        toggleServerProxy.checked = allowServerProxy;
        toggleServerProxy.addEventListener('change', (e) => {
            allowServerProxy = (e.target as HTMLInputElement).checked;
            localStorage.setItem('karin_allow_server_proxy', JSON.stringify(allowServerProxy));
        });
    }

    const toggleProxyLan = document.getElementById('toggle-proxy-lan') as HTMLInputElement | null;
    if (toggleProxyLan) {
        toggleProxyLan.checked = allowProxyLan;
        toggleProxyLan.addEventListener('change', (e) => {
            allowProxyLan = (e.target as HTMLInputElement).checked;
            localStorage.setItem('karin_allow_proxy_lan', JSON.stringify(allowProxyLan));
        });
    }

    themeToggle?.addEventListener('change', (e) => {
        const isLight = (e.target as HTMLInputElement).checked;
        if (isLight) {
            document.documentElement.setAttribute('data-theme', 'light');
            localStorage.setItem('karin_theme', 'light');
            currentTheme = 'light';
            if (themeLabel) {
                themeLabel.setAttribute('data-i18n', 'theme_light');
                themeLabel.textContent = t('theme_light');
            }
        } else {
            document.documentElement.removeAttribute('data-theme');
            localStorage.setItem('karin_theme', 'dark');
            currentTheme = 'dark';
            if (themeLabel) {
                themeLabel.setAttribute('data-i18n', 'theme_dark');
                themeLabel.textContent = t('theme_dark');
            }
        }
    });

    const karinAssistantToggle = document.getElementById('karin-assistant-toggle') as HTMLInputElement | null;
    if (karinAssistantToggle) {
        karinAssistantToggle.checked = localStorage.getItem('karin_show_assistant') !== 'false';
        karinAssistantToggle.addEventListener('change', (e) => {
            const show = (e.target as HTMLInputElement).checked;
            localStorage.setItem('karin_show_assistant', show ? 'true' : 'false');
            applyKarinAssistantVisibility();
        });
    }

    const killSwitchToggle = document.getElementById('kill-switch-toggle') as HTMLInputElement | null;
    if (killSwitchToggle) {
        killSwitchToggle.checked = localStorage.getItem('karin_kill_switch') === 'true';
        killSwitchToggle.addEventListener('change', (e) => {
            const enabled = (e.target as HTMLInputElement).checked;
            localStorage.setItem('karin_kill_switch', enabled ? 'true' : 'false');
        });
    }
    
    btnSave?.addEventListener('click', saveNewLink);
    btnImportFile?.addEventListener('click', () => { importFileInput?.click(); });
    document.getElementById('btn-ping-all')?.addEventListener('click', () => { void pingAllServers(); });

    importFileInput?.addEventListener('change', (e) => {
        const file = (e.target as HTMLInputElement).files?.[0];
        if (!file) return;

        const isOvpn = file.name.toLowerCase().endsWith('.ovpn');
        const isWg = file.name.toLowerCase().endsWith('.conf');

        if (!isOvpn && !isWg) {
            alert(t('err_invalid_file_type') || 'Ошибка: Выберите файл .ovpn или .conf');
            if (importFileInput) importFileInput.value = '';
            return;
        }

        const reader = new FileReader();
        reader.onload = (evt) => {
            const content = evt.target?.result as string;
            const safeName = encodeURIComponent(file.name);
            const payload = btoa(unescape(encodeURIComponent(content)));
            let finalLink = "";

            if (isOvpn) {
                let remote = "Unknown";
                let port = "1194";
                let proto = "UDP";

                const lines = content.split('\n').map(l => l.trim().toLowerCase());
                const protoLine = lines.find(l => l.startsWith('proto '));
                if (protoLine) {
                    if (protoLine.includes('tcp')) proto = 'TCP';
                    else if (protoLine.includes('udp')) proto = 'UDP';
                }
                const remoteLine = lines.find(l => l.startsWith('remote '));
                if (remoteLine) {
                    const parts = remoteLine.split(/\s+/);
                    if (parts.length >= 2) remote = parts[1];
                    if (parts.length >= 3) {
                        const p = parseInt(parts[2]);
                        if (!isNaN(p)) port = parts[2];
                    }
                }
                const portLine = lines.find(l => l.startsWith('port '));
                if (portLine) {
                    const parts = portLine.split(/\s+/);
                    if (parts.length >= 2) port = parts[1];
                }
                finalLink = `ovpn://${remote}:${port}?proto=${proto}&name=${safeName}&payload=${encodeURIComponent(payload)}`;
            } 
            else if (isWg) {
                let endpoint = "Unknown";
                const lines = content.split('\n').map(l => l.trim().toLowerCase());
                const endpointLine = lines.find(l => l.startsWith('endpoint'));
                if (endpointLine) {
                    const epParts = endpointLine.split('=');
                    if (epParts.length > 1) {
                        endpoint = epParts[1].trim();
                    }
                }
                finalLink = `wg://${endpoint}?name=${safeName}&payload=${encodeURIComponent(payload)}`;
            }

            if (!appLinks.find(l => l.url === finalLink)) {
                appLinks.push({ id: 'link_' + Date.now() + Math.random(), url: finalLink, pinned: false, groupId: null });
                saveData();
                renderLinks();
            } else {
                alert("Этот профиль уже добавлен!");
            }

            if (importFileInput) importFileInput.value = '';
        };
        reader.readAsText(file);
    });
    
    btnDisconnect?.addEventListener('click', disconnectProxy);
    document.getElementById('btn-manual-add')?.addEventListener('click', handleManualAdd);
    btnMenu?.addEventListener('click', () => toggleMenu());
    overlay?.addEventListener('click', () => toggleMenu(false));
  
    sidebarItems.forEach(item => { 
        item.addEventListener('click', (e) => { 
            const targetPage = (e.currentTarget as HTMLElement).dataset.target; 
            if (targetPage) switchPage(targetPage); 
        }); 
    });
  
    toggleLogs?.addEventListener('change', () => {
        if (toggleLogs?.checked) { 
            fetchLogs(); 
            logInterval = window.setInterval(fetchLogs, 1500) as unknown as number; 
        } else { 
            if (logInterval) { clearInterval(logInterval); logInterval = null; } 
        }
    });
  
    modalSearch?.addEventListener('input', () => {
        if(!modalSearch || !searchResults) return;
        const query = modalSearch.value.toLowerCase();
        const usedTags = Object.values(routingState).flat().map((t: any) => t.value);
        const filtered = allAvailableTags.filter(t => t.toLowerCase().includes(query) && !usedTags.includes(t));
        renderSearchResults(filtered); 
    });
  
    btnEditMode?.addEventListener('click', () => {
        isEditMode = !isEditMode; 
        selectedLinks.clear(); 
        selectedGroups.clear();
        if (editBar) editBar.style.display = isEditMode ? 'flex' : 'none';
        if (importBar) importBar.style.display = isEditMode ? 'none' : 'flex';
        renderLinks();
    });
  
    document.getElementById('btn-edit-cancel')?.addEventListener('click', () => {
        isEditMode = false; selectedLinks.clear(); selectedGroups.clear();
        if (editBar) editBar.style.display = 'none'; 
        if (importBar) importBar.style.display = 'flex';
        renderLinks();
    });
  
    document.getElementById('btn-edit-delete')?.addEventListener('click', () => {
        appLinks = appLinks.filter(l => !selectedLinks.has(l.id)); 
        cleanEmptyGroups();
        selectedLinks.clear(); selectedGroups.clear(); isEditMode = false;
        if (editBar) editBar.style.display = 'none'; 
        if (importBar) importBar.style.display = 'flex';
        saveData(); renderLinks();
    });
  
    document.getElementById('btn-edit-select-all')?.addEventListener('click', () => {
        const allSelected = selectedLinks.size === appLinks.length;
        if (allSelected) { 
            selectedLinks.clear(); selectedGroups.clear(); 
        } else { 
            appLinks.forEach(l => selectedLinks.add(l.id)); 
            appGroups.forEach(g => selectedGroups.add(g.id)); 
        }
        renderLinks();
    });
  
    document.getElementById('btn-edit-ungroup')?.addEventListener('click', () => {
        appLinks.forEach(l => { if (selectedLinks.has(l.id)) l.groupId = null; });
        cleanEmptyGroups(); selectedLinks.clear(); selectedGroups.clear();
        saveData(); renderLinks();
    });
  
    document.getElementById('btn-edit-rename')?.addEventListener('click', async () => {
        if (selectedGroups.size === 1) {
            const gId = Array.from(selectedGroups)[0]; 
            const g = appGroups.find(x => x.id === gId);
            if (!g) return;
            const newName = await showPrompt(t('prompt_rename_group'), g.name);
            if (newName) { g.name = newName; saveData(); renderLinks(); }
        } else { 
            alert(t('alert_select_one_group')); 
        }
    });
  
    document.getElementById('btn-edit-pin')?.addEventListener('click', () => {
        selectedGroups.forEach(gId => { const g = appGroups.find(x => x.id === gId); if (g) g.pinned = !g.pinned; });
        appLinks.forEach(l => { if (selectedLinks.has(l.id) && !l.groupId) l.pinned = !l.pinned; });
        saveData(); renderLinks();
    });
  
    document.getElementById('btn-edit-group')?.addEventListener('click', async () => {
        if (selectedLinks.size === 0) return;
        const gName = await showPrompt(t('prompt_new_group'), t('default_new_group'));
        if (gName) {
            const newGroupId = 'grp_' + Date.now();
            appGroups.push({ id: newGroupId, name: gName, pinned: false, isOpen: true });
            appLinks.forEach(l => { if (selectedLinks.has(l.id)) l.groupId = newGroupId; });
            
            selectedLinks.clear(); selectedGroups.clear(); isEditMode = false;
            if (editBar) editBar.style.display = 'none'; 
            if (importBar) importBar.style.display = 'flex';
            
            cleanEmptyGroups(); saveData(); renderLinks();
        }
    });
  
    const routeModal = document.getElementById('route-action-modal') as HTMLDialogElement | null;
    const fileInput = document.getElementById('route-file-input') as HTMLInputElement | null;
  
    document.getElementById('btn-route-action')?.addEventListener('click', () => { routeModal?.showModal(); });
    
    document.getElementById('btn-route-save')?.addEventListener('click', async () => {
        routeModal?.close();
        const name = await showPrompt(t('prompt_profile_name'));
        if (name && domType && domUrl && domIp && remType && remUrl && remIp) {
            const newProfileId = 'rp_' + Date.now();
            routeProfiles.push({
                id: newProfileId, name, defaultOutbound, rules: routingState,
                domDns: { type: domType.value, url: domUrl.value, ip: domIp.value },
                remDns: { type: remType.value, url: remUrl.value, ip: remIp.value },
                zonePriority: [...zonePriority] 
            });
            localStorage.setItem('karin_route_profiles', JSON.stringify(routeProfiles));
            setActiveRouteProfile(newProfileId);
            renderRoutingProfiles();
        }
    });
  
    document.getElementById('btn-route-import')?.addEventListener('click', () => { routeModal?.close(); fileInput?.click(); });
  
    fileInput?.addEventListener('change', (e) => {
        const file = (e.target as HTMLInputElement).files?.[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const data = JSON.parse(e.target?.result as string);
                    if (data.rules && data.domDns) {
                        data.id = 'rp_' + Date.now();
                        routeProfiles.push(data);
                        localStorage.setItem('karin_route_profiles', JSON.stringify(routeProfiles));
                        renderRoutingProfiles();
                    }
                } catch(err) { alert(t('err_parse_file')); }
            };
            reader.readAsText(file);
        }
    });
    void initBridge();
    checkApplicationUpdates();
}

// **********************************
// GLOBAL EVENT DELEGATION
// **********************************
document.addEventListener('click', async (e) => {
    const target = e.target as HTMLElement;

    if (target.closest('[data-subpage-close]')) { closeZonePage(); return; }
    const zoneCard = target.closest<HTMLElement>('[data-zone-open]');
    if (zoneCard) {
        if (Date.now() >= suppressZoneClickUntil) openZonePage(zoneCard.dataset.zoneOpen as ZoneKey);
        return;
    }
    const makeDefault = target.closest<HTMLElement>('[data-zone-default]');
    if (makeDefault) {
        defaultOutbound = makeDefault.dataset.zoneDefault as ZoneKey;
        localStorage.setItem('karin_default_outbound', defaultOutbound);
        updateDefaultOutboundUI();
        renderRouting();
        return;
    }
    const moveZone = target.closest<HTMLElement>('[data-zone-move]');
    if (moveZone && openZone) {
        const from = zonePriority.indexOf(openZone);
        const to = from + Number(moveZone.dataset.zoneMove);
        if (to >= 0 && to < zonePriority.length) {
            zonePriority.splice(to, 0, zonePriority.splice(from, 1)[0]);
            localStorage.setItem('karin_zone_priority', JSON.stringify(zonePriority));
            applyColumnOrder();
            renderRouting();
        }
        return;
    }
  
    const col = target.closest('.route-column');
    if (col && !target.closest('.btn-add') && !target.closest('.btn-delete-tag') && !target.closest('.tag-item')) {
      defaultOutbound = (col as HTMLElement).dataset.zone as ZoneKey;
      localStorage.setItem('karin_default_outbound', defaultOutbound); 
      updateDefaultOutboundUI();
    }
  
    const isMenuDot = target.closest('.btn-menu-dots');
    const isDropdown = target.closest('.dropdown-menu');
    const isCustomSelect = target.closest('.custom-select-btn'); 
    
    if (!isMenuDot && !isDropdown && !isCustomSelect) { 
        document.querySelectorAll('.dropdown-menu').forEach(m => (m as HTMLElement).style.display = 'none'); 
    }
  
    if (target.id === 'btn-ping' || target.closest('#btn-ping')) {
      if(btnPing) btnPing.innerText = "...";
      invoke<string>('check_ping').then(res => { if(btnPing) btnPing.innerText = res; }).catch(() => { if(btnPing) btnPing.innerText = "Error"; });
    }
  
    if (target.classList.contains('btn-add')) { 
        currentZone = target.dataset.zone as ZoneKey; 
        searchModal?.showModal(); 
        modalSearch?.focus(); 
    }
    
    if (target.classList.contains('btn-delete-tag')) {
      const tag = target.dataset.tag!; const zone = target.dataset.zone as ZoneKey;
      routingState[zone] = routingState[zone].filter((t: any) => t.value !== tag); renderRouting();
    }
  
    const selectableItem = target.closest('.link-item[data-select-url]') as HTMLElement | null;
    if (selectableItem && !isEditMode && !target.closest('.link-actions')) {
        selectProfile(selectableItem.dataset.selectUrl!);
        profilesDrawer?.close();
    }
  
    if (target.classList.contains('edit-checkbox') && !target.hasAttribute('data-group-id')) {
        const id = target.dataset.id!;
        if ((target as HTMLInputElement).checked) selectedLinks.add(id); else selectedLinks.delete(id);
    }
  
    const groupHeader = target.closest('.group-header');
    if (groupHeader && !target.closest('.edit-checkbox')) {
        const gId = (groupHeader as HTMLElement).dataset.id!;
        const group = appGroups.find(g => g.id === gId);
        if (group) { group.isOpen = !group.isOpen; saveData(); renderLinks(); }
    }
  
    if (isMenuDot) {
      const btn = isMenuDot as HTMLElement; 
      const index = btn.dataset.index;
      const isRoute = btn.classList.contains('btn-route-menu-dots');
      const menuId = isRoute ? `route-menu-${index}` : `menu-${index}`;
      const menu = document.getElementById(menuId);
      const isCurrentlyOpen = menu?.style.display === 'flex';
      
      document.querySelectorAll('.dropdown-menu').forEach(m => (m as HTMLElement).style.display = 'none');
      
      if (menu && !isCurrentlyOpen) {
        menu.style.display = 'flex'; menu.style.top = '100%'; menu.style.bottom = 'auto'; menu.style.marginTop = '8px'; menu.style.marginBottom = '0';
        const container = isRoute ? document.getElementById('routing-profiles-list') : linksContainer;
        if (container) {
            const menuRect = menu.getBoundingClientRect(); const containerRect = container.getBoundingClientRect();
            if (menuRect.bottom > containerRect.bottom) { menu.style.top = 'auto'; menu.style.bottom = '100%'; menu.style.marginTop = '0'; menu.style.marginBottom = '8px'; }
        }
      } else if (menu && isCurrentlyOpen) {
          menu.style.display = 'none';
      }
    }
  
    if (target.classList.contains('btn-share') && !target.closest('.btn-export-profile')) {
      navigator.clipboard.writeText(target.dataset.url!).then(() => {
        const originalText = target.innerText; target.innerText = t('btn_copied') || 'Скопировано!';
        setTimeout(() => { target.innerText = originalText; const menu = target.closest('.dropdown-menu') as HTMLElement; if (menu) menu.style.display = 'none'; }, 1000);
      }).catch(() => alert('Copy Error'));
    }
  
    if (target.classList.contains('btn-pin') && !target.closest('#edit-bar')) {
        const id = target.dataset.id;
        const link = appLinks.find(l => l.id === id);
        if (link) { link.pinned = !link.pinned; saveData(); renderLinks(); }
        const menu = target.closest('.dropdown-menu') as HTMLElement; if (menu) menu.style.display = 'none';
    }
  
    if (target.classList.contains('btn-delete-link')) {
        const id = target.dataset.id;
        appLinks = appLinks.filter(l => l.id !== id);
        cleanEmptyGroups(); saveData(); renderLinks();
    }
    
    const loadBtn = target.closest('.btn-load-profile') as HTMLElement;
    if (loadBtn) {
        try {
            const p = routeProfiles.find(x => x.id === loadBtn.dataset.id);
            if (p) {
                applyRouteProfile(p);
                setActiveRouteProfile(p.id);
                
                const orig = loadBtn.innerText;
                loadBtn.innerText = t('status_applied');
                setTimeout(() => { loadBtn.innerText = orig; }, 1500);
            }
        } catch (err) {
            console.error(err); alert(t('err_apply_profile'));
        }
    }
  
    const delBtn = target.closest('.btn-del-profile') as HTMLElement;
    if (delBtn) {
        if (activeRouteProfileId === delBtn.dataset.id) setActiveRouteProfile(null);
        routeProfiles = routeProfiles.filter(x => x.id !== delBtn.dataset.id);
        localStorage.setItem('karin_route_profiles', JSON.stringify(routeProfiles)); 
        renderRoutingProfiles();
    }
  
    const editBtn = target.closest('.btn-edit-profile') as HTMLElement;
    if (editBtn) {
        const p = routeProfiles.find(x => x.id === editBtn.dataset.id);
        if (p) {
            const newName = await showPrompt(t('prompt_new_name'), p.name);
            if (newName) { 
                p.name = newName; 
                localStorage.setItem('karin_route_profiles', JSON.stringify(routeProfiles)); 
                renderRoutingProfiles(); 
            }
        }
        const menu = target.closest('.dropdown-menu') as HTMLElement; if (menu) menu.style.display = 'none';
    }
  
    const exportBtn = target.closest('.btn-export-profile') as HTMLElement;
    if (exportBtn) {
        const p = routeProfiles.find(x => x.id === exportBtn.dataset.id);
        if (p) {
            const jsonStr = JSON.stringify(p, null, 2);
            invoke('export_profile', { 
                filename: `routing_${p.name}.json`, 
                content: jsonStr 
            }).then((res) => {
                console.log(res);
            }).catch((err) => {
                if (err !== "Отменено") alert(`${t('err_export')} ${err}`);
            });
        }
        const menu = target.closest('.dropdown-menu') as HTMLElement; if (menu) menu.style.display = 'none';
    }
});

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}