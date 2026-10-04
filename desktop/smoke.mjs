import * as electron from 'electron';
import assert from 'node:assert/strict';
import {mkdtemp, readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:http';
import {once} from 'node:events';
import {createDesktopHost} from './host.mjs';
import {CLOUD_URL, OFFLINE_URL} from './host-policy.mjs';

async function run() {
const profile = await mkdtemp(join(tmpdir(), 'desktop-host-smoke-'));
electron.app.setPath('userData', profile);
electron.app.disableHardwareAcceleration();
const errors = [];
const opened = [];
const startOnline = process.argv.includes('--online-start');
const navigation = [];
let disconnected = false;
let subscriber;
let disposed = false;
let initialized = false;
let finishInitialization;
let startCalls = 0;
const initialization = new Promise(resolve => {finishInitialization = resolve;});
const settings = {revision: 1, pairs: [{id: 'documents', remotePath: '/Documents', mountPoint: join(profile, 'Documents')}],
    pollInterval: 5, launchOnStartup: false, minimizeToTray: true, cliAvailable: true, cliPath: 'bundled pc'};
const snapshot = {revision: 1, state: 'running', notice: null, cliAvailable: true, pairs: settings.pairs.map(pair => ({...pair,
    state: 'running', error: null, status: {online: true, pendingCount: 0, failedCount: 0, failedDownloadCount: 0,
        deferredCount: 0, nextDueSeconds: 0, cacheUsed: 0, cacheMax: 1073741824, lastPoll: 0, uptime: 60}}))};
const engine = {
    initialize: () => initialization, dispose: async () => {disposed = true;},
    subscribe: callback => {subscriber = callback; return () => {subscriber = null;};},
    getSettings: async () => {assert.equal(initialized, true); return settings;},
    status: async () => {assert.equal(initialized, true); return snapshot;},
    files: async () => ({files: []}), conflicts: async () => ({conflicts: []}), activity: async () => ({activity: []}),
    start: async () => {assert.equal(initialized, true); startCalls++; return {ok: true, status: snapshot};},
    stop: async () => ({ok: true, status: snapshot}),
};
let partition;
const shim = {...electron,
    BrowserWindow: class {
        constructor(options) {
            const window = new electron.BrowserWindow(options);
            window.webContents.on('did-navigate', (_event, url) => navigation.push(url));
            return window;
        }
    },
    shell: {...electron.shell, openExternal: async url => {opened.push(url);}},
    session: {fromPartition: name => {
        partition = electron.session.fromPartition(name);
        partition.protocol.handle('https', () => disconnected
            ? new Response('Unavailable', {status: 503})
            : new Response('<!doctype html><html><body><h1>Cloud fixture</h1></body></html>', {headers: {'Content-Type': 'text/html'}}));
        return partition;
    }},
};
let host;
let cookieServer;
let cookieWindow;
const watchdog = setTimeout(() => {
    console.error('Desktop smoke timed out.');
    electron.app.exit(1);
}, 30000);
try {
    console.log('Starting isolated desktop host.');
    host = await createDesktopHost(shim, () => engine, {offline: !startOnline, hidden: true});
    console.log(startOnline ? 'Loaded cloud first without opening Sync.' : 'Loaded bundled settings.');
    host.window.webContents.on('console-message', event => {
        if (event.level === 'error' && !event.message.includes('Electron Security Warning')) errors.push(event.message);
    });
    const inspect = script => host.window.webContents.executeJavaScript(script);
    assert.deepEqual(navigation, [startOnline ? CLOUD_URL : OFFLINE_URL]);
    assert.equal(initialized, false);
    assert.equal(await inspect('typeof window.PigcloudSyncEngine.start'), 'function');
    await inspect(`window.PigcloudSyncEngine.start({}).then(() => {window.desktopStartFinished = true;}); true`);
    await inspect('new Promise(resolve => setTimeout(resolve, 50))');
    if (startOnline) assert.equal(await inspect("document.querySelector('#settings-page')"), null);
    else assert.ok(await inspect("document.querySelector('#settings-page').getBoundingClientRect().width > 0"));
    assert.equal(startCalls, 0);
    assert.equal(await inspect('Boolean(window.desktopStartFinished)'), false);
    initialized = true;
    finishInitialization(snapshot);
    assert.equal(await host.ready, true);
    await inspect('new Promise(resolve => setTimeout(resolve, 50))');
    assert.equal(startCalls, 1);
    const hide = host.window.hide.bind(host.window);
    let hiddenByMinimize = false;
    host.window.hide = () => {hiddenByMinimize = true; hide();};
    host.window.emit('minimize');
    assert.equal(hiddenByMinimize, false);
    host.window.hide = hide;
    if (startOnline) await host.window.loadURL(OFFLINE_URL);
    console.log('Loaded shared UI before initialization and queued native operations safely.');
    await inspect(`new Promise((resolve, reject) => {
        const deadline = Date.now() + 8000;
        const tick = () => {
            if (document.querySelector('#settings-panel-sync')?.textContent.includes('Documents')) return resolve();
            if (Date.now() > deadline) return reject(new Error(document.body.innerText));
            setTimeout(tick, 50);
        };
        tick();
    })`);
    console.log('Rendered native sync status.');
    assert.equal(await inspect('typeof window.PigcloudSyncEngine.status'), 'function');
    assert.equal(await inspect('typeof process'), 'undefined');
    assert.equal(await inspect('typeof require'), 'undefined');
    assert.equal((await inspect('window.PigcloudSyncEngine.status()')).state, 'running');
    const preferences = host.window.webContents.getLastWebPreferences();
    assert.equal(preferences.sandbox, true);
    assert.equal(preferences.contextIsolation, true);
    assert.equal(preferences.nodeIntegration, false);
    assert.ok(await inspect("document.querySelector('#settings-panel-sync').getBoundingClientRect().width > 0"));
    const response = await host.serve({url: 'pigcloud-app://settings/index.html', method: 'GET'});
    assert.match(response.headers.get('Content-Security-Policy'), /connect-src 'none'/);
    assert.equal((await host.serve({url: 'pigcloud-app://settings/%2e%2e%2fpackage.json', method: 'GET'})).status, 404);
    await host.openCloud();
    assert.equal(await inspect('typeof window.PigcloudSyncEngine.status'), 'function');
    assert.equal(await inspect('typeof require'), 'undefined');
    cookieServer = createServer((request, response) => {
        if (request.url === '/set') {
            response.setHeader('Set-Cookie', 'desktop_smoke=only-native; HttpOnly; SameSite=Lax; Path=/');
            response.end('ok');
        } else if (request.url === '/read') {
            response.setHeader('Content-Type', 'application/json');
            response.end(JSON.stringify({cookie: request.headers.cookie || ''}));
        } else {
            response.setHeader('Content-Type', 'text/html');
            response.setHeader('Content-Security-Policy', "default-src 'none'");
            response.end('<!doctype html><html><body>Cookie fixture</body></html>');
        }
    });
    cookieServer.listen(0, '127.0.0.1');
    await once(cookieServer, 'listening');
    const cookieOrigin = `http://127.0.0.1:${cookieServer.address().port}`;
    await partition.fetch(`${cookieOrigin}/set`, {credentials: 'include'});
    const cookieReply = await partition.fetch(`${cookieOrigin}/read`, {credentials: 'include'});
    assert.equal((await cookieReply.json()).cookie, 'desktop_smoke=only-native');
    const cookies = await partition.cookies.get({url: cookieOrigin});
    assert.equal(cookies.find(cookie => cookie.name === 'desktop_smoke').httpOnly, true);
    cookieWindow = new electron.BrowserWindow({show: false,
        webPreferences: {session: partition, sandbox: true, contextIsolation: true, nodeIntegration: false}});
    await cookieWindow.loadURL(cookieOrigin);
    assert.equal(await cookieWindow.webContents.executeJavaScript('document.cookie'), '');
    assert.equal(await cookieWindow.webContents.executeJavaScript('typeof window.PigcloudSyncEngine'), 'undefined');
    cookieWindow.destroy();
    cookieServer.close();
    console.log('Verified native session cookies and renderer HttpOnly isolation.');
    await inspect(`new Promise(resolve => {
        const frame = document.createElement('iframe');
        frame.onload = () => resolve(typeof frame.contentWindow.PigcloudSyncEngine);
        frame.src = '/child'; document.body.appendChild(frame);
    })`).then(value => assert.equal(value, 'undefined'));
    disconnected = true;
    await host.openCloud();
    await inspect(`new Promise(resolve => setTimeout(resolve, 150))`);
    assert.match(host.window.webContents.getURL(), /^pigcloud-app:\/\/settings\//);
    assert.equal((await inspect('window.PigcloudSyncEngine.status()')).pairs[0].id, 'documents');
    disconnected = false;
    await host.openCloud();
    assert.match(host.window.webContents.getURL(), /^https:\/\/pigcloud.de\/cloud\//);
    const recovered = once(host.window.webContents, 'did-finish-load');
    host.window.webContents.forcefullyCrashRenderer();
    await Promise.race([recovered, new Promise((_resolve, reject) => setTimeout(() => reject(new Error('Renderer recovery timed out.')), 8000))]);
    assert.match(host.window.webContents.getURL(), /^pigcloud-app:\/\/settings\//);
    assert.equal((await inspect('window.PigcloudSyncEngine.status()')).state, 'running');
    assert.match(await readFile(join(profile, 'desktop.log'), 'utf8'), /renderer_gone/);
    assert.equal(opened.length, 0);
    assert.deepEqual(errors, []);
    await host.dispose();
    assert.equal(disposed, true);
    assert.equal(subscriber, null);
    clearTimeout(watchdog);
    console.log('Desktop smoke passed: shared offline UI, sandbox, native IPC, remote return, child-frame exclusion and shutdown.');
    electron.app.exit(0);
} catch (error) {
    clearTimeout(watchdog);
    console.error(error);
    cookieWindow?.destroy();
    cookieServer?.close();
    electron.app.exit(1);
}
}

run().catch(error => {
    console.error(error);
    electron.app.exit(1);
});
