const {contextBridge, ipcRenderer} = require('electron');

const url = new URL(globalThis.location.href);
const trusted = !url.username && !url.password && (url.origin === 'https://pigcloud.de'
    || (url.protocol === 'pigcloud-app:' && url.hostname === 'settings' && !url.port));

if (process.isMainFrame && trusted) {
    const invoke = async (name, value) => {
        const result = await ipcRenderer.invoke(`pigcloud:sync:${name}`, value);
        const code = result && typeof result === 'object' ? result.__pigcloudNativeFailure : undefined;
        if (typeof code === 'string') throw new Error(`pigcloud-native:${code}`);
        return result;
    };
    contextBridge.exposeInMainWorld('PigcloudSyncEngine', Object.freeze({
        capabilities: () => invoke('capabilities'),
        getSettings: () => invoke('getSettings'),
        saveSettings: value => invoke('saveSettings', value),
        status: () => invoke('status'),
        reportAppearance: value => invoke('reportAppearance', value),
        getAppearance: () => invoke('getAppearance'),
        start: value => invoke('start', value),
        stop: value => invoke('stop', value),
        unlock: value => invoke('unlock', value),
        files: value => invoke('files', value),
        activity: value => invoke('activity', value),
        conflicts: value => invoke('conflicts', value),
        resolve: value => invoke('resolve', value),
        retry: value => invoke('retry', value),
        flush: value => invoke('flush', value),
        release: value => invoke('release', value),
        pickFolder: () => invoke('pickFolder'),
        pickCli: () => invoke('pickCli'),
        resetCli: () => invoke('resetCli'),
        openFolder: value => invoke('openFolder', value),
        openCloud: () => invoke('openCloud'),
        openUpdates: () => invoke('openUpdates'),
        checkUpdates: () => invoke('checkUpdates'),
        installUpdate: () => invoke('installUpdate'),
        openAccountSettings: () => invoke('openAccountSettings'),
        login: () => invoke('login'),
        loginCli: value => invoke('loginCli', value),
        cancelLoginCli: () => invoke('cancelLoginCli'),
        subscribe: callback => {
            if (typeof callback !== 'function') throw new TypeError('A subscription needs a callback.');
            const listener = (_event, value) => callback(value);
            ipcRenderer.on('pigcloud:sync:changed', listener);
            return () => ipcRenderer.removeListener('pigcloud:sync:changed', listener);
        },
    }));
}
