import {syncBusy} from './host-updates.mjs';

export const SYSTEM_GROUND = Object.freeze({light: '#F1F2F8', dark: '#121212'});
export const JUMP_ARGUMENTS = Object.freeze({cloud: '--open-cloud', sync: '--open-sync', toggle: '--toggle-sync'});
const RUNNING_STATES = new Set(['running', 'starting']);

export function followsSystem(appearance) {
    return !appearance || appearance.theme === 'auto';
}

export function paintFor(appearance, systemUsesDark) {
    const systemBase = systemUsesDark ? 'dark' : 'light';
    if (followsSystem(appearance)) {
        return {
            base: systemBase,
            background: appearance?.base === systemBase ? appearance.background : SYSTEM_GROUND[systemBase],
            themeSource: 'system',
        };
    }
    return {base: appearance.base, background: appearance.background, themeSource: appearance.base};
}

export function systemUsesDark(nativeTheme, platform, lastSeen) {
    if (platform === 'win32' && typeof nativeTheme.shouldUseDarkColorsForSystemIntegratedUI === 'boolean') {
        return nativeTheme.shouldUseDarkColorsForSystemIntegratedUI;
    }
    if (!nativeTheme.themeSource || nativeTheme.themeSource === 'system') return Boolean(nativeTheme.shouldUseDarkColors);
    return lastSeen;
}

export function windowIconName(appearance) {
    const theme = appearance?.theme;
    return ['light', 'dark', 'mocha', 'piggy'].includes(theme) ? `window-${theme}.png` : 'icon.png';
}

export function progressValue(snapshot) {
    return syncBusy(snapshot) ? 2 : -1;
}

export function attentionCount(snapshot) {
    let waiting = 0;
    for (const pair of snapshot?.pairs || []) {
        waiting += (Number(pair.status?.failedCount) || 0) + (Number(pair.status?.failedDownloadCount) || 0);
    }
    return waiting;
}

export function badgeLabel(count, t) {
    return count > 99 ? '99+' : count > 0 ? String(count) : t('desktopNativeAttentionNone');
}

export const OVERLAY_SIZE = 16;
const OVERLAY_BGR = [145, 55, 179];
const OVERLAY_RIM = [255, 255, 255];

export function overlayBitmap(size = OVERLAY_SIZE) {
    const buffer = Buffer.alloc(size * size * 4);
    const centre = (size - 1) / 2;
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
        const distance = Math.hypot(x - centre, y - centre);
        if (distance > centre) continue;
        const channels = distance > centre - 1.5 ? OVERLAY_RIM : OVERLAY_BGR;
        const offset = (y * size + x) * 4;
        [buffer[offset], buffer[offset + 1], buffer[offset + 2]] = channels;
        buffer[offset + 3] = 255;
    }
    return buffer;
}

export function anyRunning(snapshot) {
    return (snapshot?.pairs || []).some(pair => RUNNING_STATES.has(pair.state));
}

export function jumpAction(argv) {
    for (const [action, flag] of Object.entries(JUMP_ARGUMENTS)) if (argv.includes(flag)) return action;
    return null;
}

function entries(snapshot, t) {
    return [
        {action: 'cloud', label: t('desktopNativeOpen')},
        {action: 'sync', label: t('desktopNativeSettings')},
        {action: 'toggle', label: t(anyRunning(snapshot) ? 'desktopNativePause' : 'desktopNativeResume')},
    ];
}

export function shellMenuKey(snapshot, t) {
    return entries(snapshot, t).map(entry => entry.label).join('\n');
}

export function jumpListTemplate(snapshot, t, program) {
    return [{
        type: 'tasks',
        items: entries(snapshot, t).map(({action, label}) => ({
            type: 'task', title: label, description: label, program, args: JUMP_ARGUMENTS[action],
        })),
    }];
}

export function dockMenuTemplate(snapshot, t, run) {
    return entries(snapshot, t).map(({action, label}) => ({label, click: () => run(action)}));
}
