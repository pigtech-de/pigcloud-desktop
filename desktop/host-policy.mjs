export const CLOUD_ORIGIN = 'https://pigcloud.de';
export const CLOUD_URL = `${CLOUD_ORIGIN}/cloud/`;
export const OFFLINE_URL = 'pigcloud-app://settings/index.html';
export const UPDATE_OWNER = 'pigtech-de';
export const UPDATE_REPOSITORY = 'pigcloud-desktop';
export const RELEASE_URL = `https://github.com/${UPDATE_OWNER}/${UPDATE_REPOSITORY}/releases/latest`;
export const UPDATE_FEED = Object.freeze({
    provider: 'github', owner: UPDATE_OWNER, repo: UPDATE_REPOSITORY,
    protocol: 'https', private: false, publishAutoUpdate: true,
});
export const ACCOUNT_URL = 'https://pigcloud.de/cloud/#!settings/connected-accounts';
export const IPC_PREFIX = 'pigcloud:sync:';
export const CHANGE_CHANNEL = `${IPC_PREFIX}changed`;

export function allowsPermission(contents, ownedContents, permission, details) {
    return contents === ownedContents && details.isMainFrame === true
        && isTrustedUrl(contents?.mainFrame?.url) && isTrustedUrl(details.requestingUrl)
        && ['clipboard-sanitized-write', 'fullscreen', 'screen-wake-lock'].includes(permission);
}

export function isTrustedUrl(value) {
    try {
        const url = new URL(value);
        if (url.username || url.password) return false;
        return url.origin === CLOUD_ORIGIN
            || (url.protocol === 'pigcloud-app:' && url.hostname === 'settings' && !url.port);
    } catch {
        return false;
    }
}

export function requireTrustedSender(event, contents) {
    if (!contents || contents.isDestroyed() || event.sender !== contents
        || !event.senderFrame || event.senderFrame !== contents.mainFrame
        || !isTrustedUrl(event.senderFrame.url)) {
        throw new Error('This page cannot access desktop sync.');
    }
}

export function externalUrl(value) {
    try {
        const url = new URL(value);
        if (url.username || url.password) return null;
        return ['https:', 'mailto:'].includes(url.protocol) ? url.href : null;
    } catch {
        return null;
    }
}

export function cloudNavigation(value) {
    try {
        const url = new URL(value);
        if (url.protocol !== 'https:' || url.port || url.username || url.password) return null;
        if (!['pigcloud.de', 'www.pigcloud.de'].includes(url.hostname)) return null;
        url.hostname = 'pigcloud.de';
        return url.href;
    } catch {
        return null;
    }
}

export function bundlePath(value) {
    try {
        const url = new URL(value);
        if (url.protocol !== 'pigcloud-app:' || url.hostname !== 'settings'
            || url.port || url.username || url.password || url.search) return null;
        const path = decodeURIComponent(url.pathname);
        if (path.includes('\\') || path.includes('\0') || path.split('/').some(part => part === '..' || part === '.')) return null;
        return path === '/' ? 'index.html' : path.slice(1);
    } catch {
        return null;
    }
}

export function requireObject(value, allowed) {
    if (!value || typeof value !== 'object' || Array.isArray(value)
        || Object.keys(value).some(key => !allowed.includes(key))) {
        throw new Error('Invalid desktop request.');
    }
    return value;
}

export function deviceVerificationUrl({verificationUrl, userCode}) {
    try {
        const url = new URL(verificationUrl);
        if (url.origin !== CLOUD_ORIGIN || url.username || url.password || url.pathname !== '/activate'
            || !/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(userCode)
            || url.searchParams.size !== 1 || url.searchParams.get('code') !== userCode
            || !/^#k=[A-Za-z0-9_-]{43}$/.test(url.hash)) return null;
        return url.href;
    } catch {
        return null;
    }
}
