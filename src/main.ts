import { invoke } from "@tauri-apps/api/core";
import { translations } from "./i18n";

// **********************************
// TYPES & INTERFACES
// **********************************
interface ProxyGroup { id: string; name: string; pinned: boolean; isOpen: boolean; }
interface ProxyLink { id: string; url: string; pinned: boolean; groupId: string | null; }
interface DnsConfig { type: string, url: string, ip: string }
interface RouteProfile { id: string, name: string, defaultOutbound: string, rules: any, domDns?: DnsConfig, remDns?: DnsConfig }
interface RoutingRule { type: string; value: string; }
type ZoneKey = 'direct' | 'proxy' | 'block';

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
let allAvailableTags: string[] = [];
let currentZone: ZoneKey = 'proxy';
let defaultOutbound: ZoneKey = 'proxy';
let isEditMode = false;
let selectedLinks = new Set<string>();
let selectedGroups = new Set<string>();
let logInterval: number | null = null; 

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
    return p;
});

function saveData() {
    localStorage.setItem('karin_groups', JSON.stringify(appGroups));
    localStorage.setItem('karin_links', JSON.stringify(appLinks));
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
const btnImportOvpn = document.getElementById('btn-import-ovpn') as HTMLButtonElement | null;
const ovpnFileInput = document.getElementById('ovpn-file-input') as HTMLInputElement | null;

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
    en: "English",
    ru: "Русский",
    fr: "Français",
    tr: "Türkçe",
    zh: "中文"
};

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

function updateUIStrings() {
    document.querySelectorAll('[data-i18n]').forEach(el => { 
        const key = el.getAttribute('data-i18n'); 
        if (key) el.textContent = t(key); 
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => { 
        const key = el.getAttribute('data-i18n-placeholder'); 
        if (key) (el as HTMLInputElement).placeholder = t(key); 
    });
}

// **********************************
// KARIN TERMINAL ASSISTANT LOGIC
// **********************************
const karinConsole = document.getElementById('karin-msg') as HTMLSpanElement | null;
let karinTypingTimer: number | null = null;
let karinIdleTimer: number | null = null;

function typeKarinMessage(key: string) {
    if (!karinConsole) return;
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
        const idleMessages = ['karin_idle_1', 'karin_idle_2', 'karin_idle_3', 'karin_idle_4', 'karin_idle_5', 'karin_idle_6', 'karin_idle_7', 'karin_idle_8', 'karin_idle_9', 'karin_idle_10', 'karin_idle_11', 'karin_idle_12', 'karin_idle_13', 'karin_idle_14', 'karin_idle_15'];
        const randomMsg = idleMessages[Math.floor(Math.random() * idleMessages.length)];
        typeKarinMessage(randomMsg);
    }, 25000); 
}

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
            const urls = await invoke<string[]>('fetch_subscription', { url: input });
            const domain = new URL(input).hostname;
            const newGroupId = 'grp_' + Date.now();
            appGroups.push({ id: newGroupId, name: domain, pinned: false, isOpen: true });
            urls.forEach(u => addLink(u, newGroupId));
            
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
        const dDns = safeParse('karin_dns_dom', {});
        const rDns = safeParse('karin_dns_rem', {});
    
        const result = await invoke('start_proxy', { 
            vlessLink: link, 
            routingState: routingState, 
            defaultOutbound: defaultOutbound,
            dnsParams: { domestic: dDns, remote: rDns }
        });
        
        if (result === "OK") { 
            activeLink = link; 
            sessionStorage.setItem('karin_active_link', link); 
            updateStatusUI(); 
            renderLinks(); 
            typeKarinMessage('karin_connect_ok');
        }
    } catch (error) { 
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
    pages.forEach(page => page.classList.toggle('active', page.id === pageId)); 
    toggleMenu(false); 
    
    if (pageId === 'page-logs' && toggleLogs?.checked) { 
        fetchLogs(); 
        logInterval = window.setInterval(fetchLogs, 1500) as unknown as number; 
    } else { 
        if (logInterval) { clearInterval(logInterval); logInterval = null; } 
    } 
}

function updateStatusUI() {
    if (activeLink) {
        if(statusText) { statusText.innerText = t('status_active'); statusText.className = "status-active"; }
        if(btnDisconnect) btnDisconnect.style.display = "block"; 
        if(btnPing) { btnPing.style.display = "block"; btnPing.innerText = t('btn_ping'); }
        if(statusIpBox) statusIpBox.style.display = "block"; 
        if(statusIp) statusIp.innerText = "...";
        invoke<string>('get_vpn_ip').then(ip => { if(statusIp) statusIp.innerText = ip; }).catch(() => { if(statusIp) statusIp.innerText = "Error"; });
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
        } else {
            displayName = `${url.hostname}:${url.port || '443'}`;
            if (url.hash) displayName = decodeURIComponent(url.hash.substring(1)) + ` (${url.hostname})`;
        } 
    }   catch (e) { 
            displayName = item.url.substring(0, 30) + '...'; 
    }

    const formattedProtocol = formatProxyInfo(item.url);
    const pinIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 6px;"><path d="M12 17v5"/><path d="M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z"/></svg>`;
    const checkboxHtml = isEditMode ? `<input type="checkbox" class="edit-checkbox" data-id="${item.id}" ${selectedLinks.has(item.id) ? 'checked' : ''}>` : '';
    const actionsHtml = isEditMode ? '' : `
        <button class="btn-connect ${isCurrentActive ? 'secondary' : ''}" data-url="${item.url}">${isCurrentActive ? t('status_active') || 'Активно' : t('btn_start')}</button>
        <button class="btn-menu-dots" data-index="${item.id}">⋮</button>
        <div class="dropdown-menu" id="menu-${item.id}" style="display:none;">
          <button class="btn-share" data-url="${item.url}">${t('btn_share')}</button>
          <button class="btn-pin" data-id="${item.id}">${item.pinned ? t('btn_unpin') : t('btn_pin')}</button>
          <button class="btn-delete-link danger" style="background: transparent; color: var(--danger);" data-id="${item.id}">${t('btn_delete')}</button>
        </div>
    `;

    return `
      <div class="link-item">
        ${checkboxHtml}
        <div class="link-info">
          <div class="link-name" style="font-size: 14.5px; display: flex; align-items: center; ${isCurrentActive ? 'color: var(--success); font-weight: bold;' : 'font-weight: 500;'}">
            ${item.pinned && !item.groupId ? pinIcon : ''}${displayName}
          </div>
          <div class="link-url" style="font-size: 12px; color: var(--text-dim); opacity: 0.95; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; letter-spacing: 0.3px;">
            ${formattedProtocol}
          </div>
        </div>
        <div class="link-actions">${actionsHtml}</div>
      </div>
    `;
}

function renderLinks() {
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
          <div class="group-header" data-id="${g.id}">
              <div style="display: flex; align-items: center; gap: 8px;">
                  ${isEditMode ? `<input type="checkbox" class="edit-checkbox" data-group-id="${g.id}" ${selectedGroups.has(g.id) ? 'checked' : ''} onclick="event.stopPropagation()">` : ''}
                  ${g.pinned ? pinIcon : ''} <span>${g.name}</span> <span style="font-size:12px; color:var(--text-dim);">(${gLinks.length})</span>
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
            zone.innerHTML = `<button class="btn-add" data-zone="${key}">+</button>`; 
            if (routingState[key as ZoneKey]) {
                routingState[key as ZoneKey].forEach((rule: any) => { 
                    const el = document.createElement('div'); 
                    el.className = 'tag-item'; 
                    el.innerHTML = `${rule.value} <span class="btn-delete-tag" data-tag="${rule.value}" data-zone="${key}" style="pointer-events: auto;">×</span>`; 
                    zone.appendChild(el); 
                }); 
            }
        }
    }); 
    localStorage.setItem('karin_routing', JSON.stringify(routingState)); 
}

function renderRoutingProfiles() {
    const list = document.getElementById('routing-profiles-list');
    if (!list) return;
    list.innerHTML = '';
    routeProfiles.forEach(p => {
        list.innerHTML += `
            <div class="profile-item">
                <span>${p.name}</span>
                <div class="link-actions">
                    <button class="secondary btn-load-profile" data-id="${p.id}" style="padding: 6px 12px; font-size: 13px;">${t('btn_select')}</button>
                    <button class="btn-menu-dots btn-route-menu-dots" data-index="${p.id}">⋮</button>
                    <div class="dropdown-menu" id="route-menu-${p.id}" style="display:none;">
                        <button class="btn-edit-profile" data-id="${p.id}">${t('btn_rename')}</button>
                        <button class="btn-export-profile" data-id="${p.id}">${t('btn_share')}</button>
                        <button class="btn-del-profile danger" style="background: transparent; color: var(--danger);" data-id="${p.id}">${t('btn_delete')}</button>
                    </div>
                </div>
            </div>
        `;
    });
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
        const CURRENT_VERSION = "1.2.0"; 

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
            checkApplicationUpdates();
        });
    });

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
    
    btnSave?.addEventListener('click', saveNewLink);
    btnImportOvpn?.addEventListener('click', () => { ovpnFileInput?.click(); });

    ovpnFileInput?.addEventListener('change', (e) => {
        const file = (e.target as HTMLInputElement).files?.[0];
        if (file) {
            if (!file.name.toLowerCase().endsWith('.ovpn')) {
                alert(t('err_invalid_file_type') || 'Ошибка: Пожалуйста, выберите файл профиля с расширением .ovpn');
                if (ovpnFileInput) ovpnFileInput.value = '';
                return;
            }

            const reader = new FileReader();
            reader.onload = (evt) => {
                const content = evt.target?.result as string;
                
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

                const payload = btoa(unescape(encodeURIComponent(content)));
                const safeName = encodeURIComponent(file.name);
                const ovpnLink = `ovpn://${remote}:${port}?proto=${proto}&name=${safeName}&payload=${encodeURIComponent(payload)}`;

                if (!appLinks.find(l => l.url === ovpnLink)) {
                    appLinks.push({ id: 'link_' + Date.now() + Math.random(), url: ovpnLink, pinned: false, groupId: null });
                    saveData();
                    renderLinks();
                } else {
                    alert("Этот профиль OpenVPN уже добавлен!");
                }

                if (ovpnFileInput) ovpnFileInput.value = '';
            };
            reader.readAsText(file);
        }
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
            routeProfiles.push({
                id: 'rp_' + Date.now(), name, defaultOutbound, rules: routingState,
                domDns: { type: domType.value, url: domUrl.value, ip: domIp.value },
                remDns: { type: remType.value, url: remUrl.value, ip: remIp.value }
            });
            localStorage.setItem('karin_route_profiles', JSON.stringify(routeProfiles));
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
    checkApplicationUpdates();
}

// **********************************
// GLOBAL EVENT DELEGATION
// **********************************
document.addEventListener('click', async (e) => {
    const target = e.target as HTMLElement;
  
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
  
    if (target.classList.contains('btn-connect')) connectProxy(target.dataset.url!);
  
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
            if (p && domType && domUrl && domIp && remType && remUrl && remIp) {
                if (p.rules) routingState = JSON.parse(JSON.stringify(p.rules)); 
                if (p.defaultOutbound) defaultOutbound = p.defaultOutbound as ZoneKey;
                
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