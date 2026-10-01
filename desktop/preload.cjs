const {contextBridge, ipcRenderer} = require('electron');

const url = new URL(globalThis.location.href);
const trusted = !url.username && !url.password && (url.origin === 'https://pigcloud.de'
    || (url.protocol === 'pigcloud-app:' && url.hostname === 'settings' && !url.port));

if (process.isMainFrame && trusted) {
    const invoke = (name, value) => ipcRenderer.invoke(`pigcloud:sync:${name}`, value);
    contextBridge.exposeInMainWorld('PigcloudSyncEngine', Object.freeze({
        capabilities: () => invoke('capabilities'),
        getSettings: () => invoke('getSettings'),
        saveSettings: value => invoke('saveSettings', value),
        status: () => invoke('status'),
        start: value => invoke('start', value),
        stop: value => invoke('stop', value),
        unlock: value => invoke('unlock', value),
        files: value => invoke('files', value),
        activity: value => invoke('activity', value),
        conflicts: value => invoke('conflicts', value),
        resolve: value => invoke('resolve', value),
        retry: value => invoke('retry', value),
        flush: value => invoke('flush', value),
        pickFolder: () => invoke('pickFolder'),
        pickCli: () => invoke('pickCli'),
        resetCli: () => invoke('resetCli'),
        openFolder: value => invoke('openFolder', value),
        openCloud: () => invoke('openCloud'),
        openUpdates: () => invoke('openUpdates'),
        openAccountSettings: () => invoke('openAccountSettings'),
        login: () => invoke('login'),
        loginCli: () => invoke('loginCli'),
        cancelLoginCli: () => invoke('cancelLoginCli'),
        subscribe: callback => {
            if (typeof callback !== 'function') throw new TypeError('A subscription needs a callback.');
            const listener = (_event, value) => callback(value);
            ipcRenderer.on('pigcloud:sync:changed', listener);
            return () => ipcRenderer.removeListener('pigcloud:sync:changed', listener);
        },
    }));
}
