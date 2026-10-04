import {RELEASE_URL, UPDATE_FEED} from './host-policy.mjs';

export const CHECK_INTERVAL = 6 * 60 * 60 * 1000;
export const STOP_DEADLINE = 30000;
const NO_RELEASE = new Set(['ERR_UPDATER_NO_PUBLISHED_VERSIONS', 'ERR_UPDATER_LATEST_VERSION_NOT_FOUND']);

function parseVersion(value) {
    const text = String(value ?? '').trim().replace(/^v/, '');
    const build = text.indexOf('+');
    const clean = build === -1 ? text : text.slice(0, build);
    const dash = clean.indexOf('-');
    const core = dash === -1 ? clean : clean.slice(0, dash);
    const pre = dash === -1 ? '' : clean.slice(dash + 1);
    const numbers = core.split('.');
    if (numbers.length !== 3 || numbers.some(part => !/^\d+$/.test(part))) return null;
    return {numbers: numbers.map(Number), pre: pre ? pre.split('.') : []};
}

export function compareVersions(left, right) {
    const a = parseVersion(left);
    const b = parseVersion(right);
    if (!a || !b) return null;
    for (let index = 0; index < 3; index++) {
        if (a.numbers[index] !== b.numbers[index]) return a.numbers[index] < b.numbers[index] ? -1 : 1;
    }
    if (Boolean(a.pre.length) !== Boolean(b.pre.length)) return a.pre.length ? -1 : 1;
    for (let index = 0; index < Math.max(a.pre.length, b.pre.length); index++) {
        const one = a.pre[index];
        const two = b.pre[index];
        if (one === two) continue;
        if (one === undefined) return -1;
        if (two === undefined) return 1;
        const numbers = [/^\d+$/.test(one), /^\d+$/.test(two)];
        if (numbers[0] && numbers[1]) return Number(one) < Number(two) ? -1 : 1;
        if (numbers[0] !== numbers[1]) return numbers[0] ? -1 : 1;
        return one < two ? -1 : 1;
    }
    return 0;
}

export function syncBusy(snapshot) {
    if (!snapshot) return false;
    if (['starting', 'stopping'].includes(snapshot.state)) return true;
    return (snapshot.pairs || []).some(pair => ['starting', 'stopping'].includes(pair.state)
        || (pair.status?.pendingCount || 0) > 0);
}

export function selfInstallable(platform = process.platform, env = process.env) {
    return platform !== 'linux' || Boolean(env.APPIMAGE);
}

export function createUpdates({updater, currentVersion, packaged = true, onChange = () => {},
    busy = () => false, stop = async () => {}, shutdown = async () => {}, record = async () => {},
    installable = selfInstallable(), interval = CHECK_INTERVAL, stopDeadline = STOP_DEADLINE,
    schedule = setInterval, cancel = clearInterval, limit = setTimeout, release = clearTimeout} = {}) {
    let state = 'idle';
    let version = '';
    let percent = 0;
    let code = '';
    let waiting = false;
    let downloaded = '';
    let allowPrerelease = false;
    let timer = null;
    let closed = false;
    let pending = null;

    const snapshot = () => ({state, version, percent, waiting, downloaded, installable,
        allowPrerelease, releaseUrl: RELEASE_URL, code});
    const publish = () => {
        if (!closed) onChange(snapshot());
    };
    const move = (next, values = {}) => {
        state = next;
        version = values.version ?? '';
        percent = values.percent ?? 0;
        code = values.code ?? '';
        if (next === 'idle' || next === 'error') waiting = false;
        publish();
    };
    const bounded = (work, reason) => new Promise((resolve, reject) => {
        const handle = limit(() => reject(new Error(reason)), stopDeadline);
        handle?.unref?.();
        Promise.resolve(work).then(resolve, reject).finally(() => release(handle));
    });

    if (updater && packaged) {
        updater.autoDownload = false;
        updater.autoInstallOnAppQuit = false;
        updater.allowDowngrade = false;
        updater.allowPrerelease = allowPrerelease;
        updater.setFeedURL(UPDATE_FEED);
        updater.on('checking-for-update', () => {
            if (!downloaded && state !== 'installing') move('checking', {version, percent: 0});
        });
        updater.on('update-not-available', () => {
            if (!downloaded && state !== 'installing') move('idle');
        });
        updater.on('update-available', info => {
            const candidate = info?.version || '';
            if (downloaded && compareVersions(candidate, downloaded) !== 1) return;
            if (compareVersions(candidate, currentVersion) !== 1) {
                move('idle', {code: 'updateRejected'});
                record('update_rejected').catch(() => {});
                return;
            }
            if (state === 'installing') return;
            if (state === 'downloading' && version === candidate) return;
            move('available', {version: candidate});
            if (installable) updater.downloadUpdate().catch(() => {});
        });
        updater.on('download-progress', progress => {
            if (state === 'available' || state === 'downloading') {
                state = 'downloading';
                percent = Math.max(0, Math.min(100, Math.round(progress?.percent || 0)));
                publish();
            }
        });
        updater.on('update-downloaded', info => {
            downloaded = info?.version || version;
            move('ready', {version: downloaded});
            settle();
        });
        updater.on('error', error => {
            if (state === 'installing') return;
            if (NO_RELEASE.has(error?.code) && !downloaded) {
                move('idle');
                return;
            }
            move('error', {version, code: error?.code === 'ERR_UPDATER_INVALID_SIGNATURE' ? 'updateSignature' : 'updateFailed'});
            record('update_failed').catch(() => {});
        });
    }

    async function install() {
        if (!downloaded || !installable) throw new Error('No update is ready to install.');
        if (busy()) {
            waiting = true;
            publish();
            return {ok: true, waiting: true};
        }
        waiting = false;
        move('installing', {version: downloaded});
        try {
            await bounded(stop(), 'update_stop_timeout');
            await bounded(shutdown(), 'update_shutdown_timeout');
        } catch (error) {
            move('error', {version: downloaded, code: 'updateStopFailed'});
            record('update_stop_failed').catch(() => {});
            throw error instanceof Error ? error : new Error('update_stop_failed');
        }
        updater.quitAndInstall(true, true);
        return {ok: true};
    }

    function settle() {
        if (!waiting || !downloaded || closed || state === 'installing' || busy()) return;
        install().catch(() => {});
    }

    function check() {
        if (closed || !updater || !packaged) {
            if (!installable && state === 'idle' && !code) move('idle', {code: 'updateUnsupported'});
            return Promise.resolve(snapshot());
        }
        if (!pending) {
            pending = Promise.resolve(updater.checkForUpdates()).catch(() => null).finally(() => {pending = null;});
        }
        return pending.then(() => snapshot());
    }

    return {
        snapshot,
        check: () => check(),
        install,
        settle,
        setPrerelease(value) {
            const next = Boolean(value);
            if (next === allowPrerelease) return;
            allowPrerelease = next;
            if (updater && packaged) updater.allowPrerelease = next;
            publish();
            check().catch(() => {});
        },
        start() {
            if (closed || timer) return;
            timer = schedule(() => {check().catch(() => {});}, interval);
            timer?.unref?.();
            check().catch(() => {});
        },
        dispose() {
            closed = true;
            if (timer) cancel(timer);
            timer = null;
            if (!updater?.removeAllListeners) return;
            updater.removeAllListeners();
            updater.on?.('error', () => {});
        },
    };
}
