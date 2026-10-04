import {realpath, stat} from 'node:fs/promises';
import {resolve} from 'node:path';
import {IPC_PREFIX, requireTrustedSender, requireObject} from './host-policy.mjs';

export function registerSyncIpc({ipcMain, contents, engine, dialog, window, capabilities, openCloud, openUpdates, openAccountSettings, login, loginCli, cancelLoginCli, shell, updates, reportAppearance, currentAppearance = () => null, t = key => key, inspectPath = realpath, inspectStat = stat}) {
    const channels = [];
    const folders = new Set();
    let picker = null;
    const guard = event => requireTrustedSender(event, contents());
    const add = (name, operation) => {
        const channel = IPC_PREFIX + name;
        channels.push(channel);
        ipcMain.handle(channel, async (event, value) => {
            guard(event);
            return operation(value, event);
        });
    };
    add('getSettings', () => engine.getSettings());
    add('status', async () => {
        const snapshot = await engine.status();
        return updates ? {...snapshot, updates: updates.snapshot()} : snapshot;
    });
    const shapes = {
        start: ['pairId'], stop: ['pairId'], unlock: ['password'], files: ['pairId'],
        activity: ['pairId'], conflicts: ['pairId'], resolve: ['pairId', 'path', 'choice'],
        retry: ['pairId', 'path'], flush: ['pairId'],
    };
    for (const [name, shape] of Object.entries(shapes)) {
        add(name, value => engine[name](requireObject(value ?? {}, shape)));
    }
    add('capabilities', () => capabilities());
    if (reportAppearance) {
        add('reportAppearance', value => reportAppearance(requireObject(value, ['theme', 'base', 'background', 'surface'])));
        add('getAppearance', () => currentAppearance());
    }
    add('saveSettings', async (value, event) => {
        requireObject(value, ['revision', 'pairs', 'pollInterval', 'launchOnStartup', 'minimizeToTray', 'allowPrerelease']);
        if (!Array.isArray(value.pairs)) throw new Error('Invalid sync folders.');
        const current = await engine.getSettings();
        for (const pair of value.pairs) {
            if (!pair || typeof pair.mountPoint !== 'string') throw new Error('Invalid sync folder.');
            const unchanged = current.pairs.some(existing => existing.id === pair.id && existing.mountPoint === pair.mountPoint);
            if (!unchanged && !folders.has(pair.mountPoint)) throw new Error('Choose the sync folder in the native folder picker.');
        }
        guard(event);
        return engine.saveSettings(value);
    });
    async function choose(kind, event) {
        if (picker) throw new Error('A native picker is already open.');
        const selection = dialog.showOpenDialog(window(), {
            title: t(kind === 'folder' ? 'desktopNativePickFolder' : 'desktopNativePickCli'),
            properties: kind === 'folder' ? ['openDirectory', 'createDirectory'] : ['openFile'],
            ...(kind === 'cli' && process.platform === 'win32' ? {filters: [{name: 'PigCloud CLI', extensions: ['exe']}]} : {}),
        });
        picker = selection;
        try {
            const result = await selection;
            guard(event);
            if (result.canceled || result.filePaths.length !== 1) return null;
            const path = await inspectPath(resolve(result.filePaths[0]));
            const entry = await inspectStat(path);
            guard(event);
            if (kind === 'folder') {
                if (!entry.isDirectory()) throw new Error('Choose a folder.');
                folders.add(path);
                return {path};
            }
            if (!entry.isFile()) throw new Error('Choose an executable file.');
            const answer = await dialog.showMessageBox(window(), {
                type: 'warning', title: t('desktopNativeUseCliTitle'),
                message: t('desktopNativeUseCliWarning'), detail: path,
                buttons: [t('desktopNativeCancel'), t('desktopNativeUseCli')], defaultId: 0, cancelId: 0, noLink: true,
            });
            guard(event);
            if (answer.response !== 1) return null;
            await engine.setCliPath(path);
            return engine.getSettings();
        } finally {
            picker = null;
        }
    }
    add('pickFolder', (_value, event) => choose('folder', event));
    add('pickCli', (_value, event) => choose('cli', event));
    add('resetCli', async () => {
        await engine.setCliPath(null);
        return engine.getSettings();
    });
    add('openFolder', async (value, event) => {
        const path = await engine.folderPath(requireObject(value, ['pairId']));
        guard(event);
        const failure = await shell.openPath(path);
        if (failure) throw new Error('The system could not open the sync folder.');
        return {success: true};
    });
    add('openCloud', () => openCloud());
    add('openUpdates', () => openUpdates());
    if (updates) {
        add('checkUpdates', () => updates.check());
        add('installUpdate', () => updates.install());
    }
    add('openAccountSettings', () => openAccountSettings());
    add('login', () => login());
    add('loginCli', () => loginCli());
    add('cancelLoginCli', () => cancelLoginCli());
    return () => {
        folders.clear();
        for (const channel of channels) ipcMain.removeHandler(channel);
    };
}
