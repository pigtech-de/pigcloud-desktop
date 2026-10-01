import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {CLOUD_URL, OFFLINE_URL, UPDATE_URL, ACCOUNT_URL, CHANGE_CHANNEL, isTrustedUrl, cloudNavigation, externalUrl, bundlePath, allowsPermission, deviceVerificationUrl} from './host-policy.mjs';
import {registerSyncIpc} from './host-ipc.mjs';
import {createStartup} from './host-startup.mjs';
import {createDesktopLogin} from './host-auth.mjs';
import {nativeStrings, trayMenu, traySummary, statusBitmap} from './host-tray.mjs';
import {createDiagnostics} from './diagnostics.mjs';
import {queueEngine} from './host-ready.mjs';

const directory = fileURLToPath(new URL('.', import.meta.url));
const CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'";

export async function createDesktopHost(electron, createEngine, {offline = false, hidden = false, directory: root = directory} = {}) {
    const {app, BrowserWindow, Tray, Menu, nativeImage, session, ipcMain, protocol, dialog, shell} = electron;
    protocol.registerSchemesAsPrivileged([{scheme: 'pigcloud-app', privileges: {standard: true, secure: true, supportFetchAPI: true}}]);
    if (!app.requestSingleInstanceLock()) {
        app.quit();
        return null;
    }
    let window;
    let tray;
    let closing = false;
    let stopped = false;
    let remoteAttempt = 0;
    let deadline;
    let removeIpc;
    let unsubscribe;
    let login;
    let settings = {minimizeToTray: false};
    let engine;
    let shutdown;
    let cliLogin;
    let cliLoginAbort;
    let trayIcon;
    let lastStatus;
    let rendererFailures = 0;
    const show = () => {
        if (!window || window.isDestroyed()) return;
        if (window.isMinimized()) window.restore();
        window.show();
        window.focus();
    };
    app.on('second-instance', show);
    app.on('activate', show);
    app.setAppUserModelId('de.pigcloud.desktop');
    await app.whenReady();
    const t = nativeStrings(JSON.parse(await readFile(join(root, 'bundle', 'translations.json'), 'utf8')), app.getLocale());
    const diagnostics = createDiagnostics(app.getPath('userData'));
    const partition = session.fromPartition('persist:pigcloud');
    const manifest = JSON.parse(await readFile(join(root, 'bundle', 'manifest.json'), 'utf8'));
    const serve = async request => {
        const path = bundlePath(request.url);
        if (request.method !== 'GET' || !path || !Object.hasOwn(manifest, path)) return new Response(null, {status: 404});
        try {
            const bytes = await readFile(join(root, 'bundle', path));
            return new Response(bytes, {headers: {
                'Content-Type': manifest[path], 'Content-Security-Policy': CSP,
                'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store',
            }});
        } catch {
            return new Response(null, {status: 404});
        }
    };
    partition.protocol.handle('pigcloud-app', serve);
    const startup = createStartup({app});
    await startup.initialize();
    engine = queueEngine(createEngine({
        bundledCliPath: app.isPackaged
            ? join(process.resourcesPath, process.platform === 'win32' ? 'pc.exe' : 'pc')
            : join(root, 'resources', process.platform === 'win32' ? 'pc.exe' : 'pc'),
        applyPreferences: next => startup.applyPreferences(next),
    }));
    window = new BrowserWindow({
        width: 1200, height: 850, minWidth: 420, minHeight: 560, show: false,
        title: 'PigCloud', icon: join(root, 'bundle', 'icon.png'),
        backgroundColor: '#121212', autoHideMenuBar: true,
        webPreferences: {
            preload: join(root, 'preload.cjs'), partition: 'persist:pigcloud',
            sandbox: true, contextIsolation: true, nodeIntegration: false,
            nodeIntegrationInWorker: false, nodeIntegrationInSubFrames: false,
            webSecurity: true, allowRunningInsecureContent: false, webviewTag: false,
            devTools: !app.isPackaged,
        },
    });
    window.webContents.setUserAgent(`${window.webContents.getUserAgent()} PigCloudDesktop`);
    partition.setPermissionRequestHandler((contents, permission, callback, details) => {
        callback(allowsPermission(contents, window.webContents, permission, details));
    });
    partition.setPermissionCheckHandler((contents, permission, _origin, details) =>
        allowsPermission(contents, window.webContents, permission, details));
    window.webContents.on('will-attach-webview', event => event.preventDefault());
    const browse = value => {
        const url = externalUrl(value);
        if (url) shell.openExternal(url).catch(() => {});
    };
    window.webContents.setWindowOpenHandler(({url}) => {
        const internal = cloudNavigation(url);
        if (internal) window.loadURL(internal).catch(() => fallback());
        else browse(url);
        return {action: 'deny'};
    });
    const guardNavigation = event => {
        const url = event.url;
        if (!event.isMainFrame) return;
        if (isTrustedUrl(url)) return;
        event.preventDefault();
        const internal = cloudNavigation(url);
        if (internal) window.loadURL(internal).catch(() => fallback());
        else browse(url);
    };
    window.webContents.on('will-navigate', guardNavigation);
    window.webContents.on('will-redirect', guardNavigation);
    partition.on('will-download', (event, item, contents) => {
        if (contents !== window.webContents || !isTrustedUrl(contents.mainFrame.url)) {
            event.preventDefault();
            return;
        }
        item.setSaveDialogOptions({title: t('desktopNativeSaveDownload')});
    });
    const fallback = async () => {
        clearTimeout(deadline);
        remoteAttempt++;
        if (closing || window.isDestroyed() || window.webContents.getURL().startsWith('pigcloud-app:')) return;
        try {
            await window.loadURL(OFFLINE_URL);
        } catch {
            if (!closing) dialog.showErrorBox(t('desktopNativeBootTitle'), t('desktopNativeBundleError'));
        }
    };
    async function openCloud() {
        const attempt = ++remoteAttempt;
        clearTimeout(deadline);
        deadline = setTimeout(() => {
            if (remoteAttempt === attempt) fallback().catch(() => {});
        }, 15000);
        try {
            await window.loadURL(CLOUD_URL);
            if (remoteAttempt === attempt) clearTimeout(deadline);
            return {success: true};
        } catch {
            if (remoteAttempt === attempt) await fallback();
            return {success: false};
        }
    }
    window.webContents.on('did-fail-load', (_event, code, _description, url, mainFrame) => {
        if (mainFrame && code !== -3 && cloudNavigation(url)) fallback().catch(() => {});
    });
    window.webContents.on('did-navigate', (_event, url, code) => {
        if (code >= 500 && cloudNavigation(url)) fallback().catch(() => {});
    });
    window.webContents.on('render-process-gone', () => {
        if (closing) return;
        diagnostics.record('renderer_gone').catch(() => {});
        rendererFailures++;
        if (rendererFailures > 2) {
            dialog.showErrorBox(t('desktopNativeBootTitle'), t('desktopNativeRendererError'));
            return;
        }
        window.loadURL(OFFLINE_URL).catch(() => {
            diagnostics.record('renderer_reload_failed').catch(() => {});
            dialog.showErrorBox(t('desktopNativeBootTitle'), t('desktopNativeRendererError'));
        });
    });
    const broadcast = value => {
        if (!window.isDestroyed() && isTrustedUrl(window.webContents.mainFrame.url)) {
            window.webContents.send(CHANGE_CHANNEL, value);
        }
    };
    login = createDesktopLogin({session: partition, openExternal: url => shell.openExternal(url), onComplete: openCloud,
        onState: state => broadcast({loginState: state})});
    const cancelLoginCli = () => {
        cliLoginAbort?.abort();
        return {ok: true};
    };
    const loginCli = () => {
        if (cliLogin) return cliLogin;
        cliLoginAbort = new AbortController();
        cliLogin = engine.loginCli({signal: cliLoginAbort.signal, openVerification: async verification => {
            const url = deviceVerificationUrl(verification);
            if (!url) throw new Error('Invalid local sync sign-in destination.');
            if (closing || cliLoginAbort.signal.aborted) throw new Error('Local sync sign-in was cancelled.');
            await shell.openExternal(url);
            dialog.showMessageBox(window, {
                type: 'info', title: t('desktopNativeConnectTitle'),
                message: t('desktopNativeSignInCode', {code: verification.userCode}),
                detail: t('desktopNativeConnectDetail'),
                buttons: [t('desktopNativeOk')],
            }).catch(() => {});
        }}).finally(() => {cliLogin = null; cliLoginAbort = null;});
        return cliLogin;
    };
    removeIpc = registerSyncIpc({ipcMain, contents: () => window.webContents, engine, dialog,
        window: () => window, capabilities: () => ({
            host: 'electron', pairs: true, tray: Boolean(tray), autostart: app.isPackaged,
            folderPicker: true, cameraRoll: false, wifiOnly: false, flush: true,
            cliPicker: true, login: true, loginCli: true,
        }), openCloud, openUpdates: () => shell.openExternal(UPDATE_URL),
        openAccountSettings: () => shell.openExternal(ACCOUNT_URL), login: async () => {
            const result = await login.login();
            dialog.showMessageBox(window, {
                type: 'info', title: t('desktopNativeSignInTitle'),
                message: t('desktopNativeSignInCode', {code: result.verificationCode}),
                detail: t('desktopNativeSignInDetail'),
                buttons: [t('desktopNativeOk')],
            }).catch(() => {});
            return result;
        }, loginCli, cancelLoginCli, shell, t});
    const openSync = () => window.loadURL(OFFLINE_URL).then(show);
    const nativeAction = action => action().catch(() => {
        diagnostics.record('native_action_failed').catch(() => {});
        openSync().catch(() => {}).then(() => dialog.showErrorBox(t('desktopNativeBootTitle'), t('desktopNativeActionError')));
    });
    const trayActions = {
        open: show, settings: () => nativeAction(openSync), quit: () => app.quit(),
        start: pairId => nativeAction(async () => {
            const state = pairId ? lastStatus?.pairs.find(pair => pair.id === pairId)?.state : lastStatus?.state;
            if (['locked', 'noCli', 'notConfigured', 'unsupportedEndpoint'].includes(state)) return openSync();
            const result = await engine.start(pairId ? {pairId} : {});
            if (result.ok === false) await openSync();
        }),
        stop: pairId => nativeAction(async () => {
            const result = await engine.stop(pairId ? {pairId} : {});
            if (result.ok === false) await openSync();
        }),
        folder: pairId => nativeAction(async () => {
            const path = await engine.folderPath({pairId});
            if (await shell.openPath(path)) throw new Error('folder_open_failed');
        }),
    };
    const refreshTray = state => {
        lastStatus = state;
        if (!tray) return;
        try {
            tray.setToolTip(traySummary(state, t).slice(0, 127));
            tray.setContextMenu(Menu.buildFromTemplate(trayMenu(state, t, trayActions)));
            const {width, height} = trayIcon.getSize();
            tray.setImage(nativeImage.createFromBitmap(statusBitmap(trayIcon.toBitmap(), width, height, state.state), {width, height}));
        } catch {
            tray?.destroy();
            tray = null;
            if (!hidden) show();
        }
    };
    unsubscribe = engine.subscribe(state => {
        broadcast(state);
        refreshTray(state);
        engine.getSettings().then(value => {settings = value;}).catch(() => {});
    });
    try {
        trayIcon = nativeImage.createFromPath(join(root, 'bundle', 'icon.png')).resize({width: 24, height: 24});
        if (trayIcon.isEmpty()) throw new Error('tray_unavailable');
        tray = new Tray(trayIcon);
        refreshTray({state: 'starting', pairs: []});
        tray?.on('click', show);
    } catch {
        tray?.destroy();
        tray = null;
    }
    const canHide = () => Boolean(tray) && process.platform !== 'linux';
    window.on('minimize', () => {
        if (!closing && settings.minimizeToTray && canHide()) window.hide();
    });
    window.on('close', event => {
        if (!closing && settings.minimizeToTray && canHide()) {
            event.preventDefault();
            window.hide();
        }
    });
    window.on('closed', () => {
        if (!closing) app.quit();
    });
    async function dispose() {
        if (closing) return;
        closing = true;
        clearTimeout(deadline);
        login.dispose();
        cancelLoginCli();
        removeIpc();
        unsubscribe();
        try {
            await engine.dispose();
        } finally {
            tray?.destroy();
            partition.protocol.unhandle('pigcloud-app');
            stopped = true;
        }
    }
    app.on('before-quit', event => {
        if (stopped) return;
        event.preventDefault();
        if (!shutdown) shutdown = dispose().catch(() => diagnostics.record('shutdown_failed')).finally(() => app.quit());
    });
    try {
        await window.loadURL(OFFLINE_URL);
    } catch (error) {
        await dispose();
        throw error;
    }
    if (!hidden && !(process.argv.includes('--minimized') && canHide())) show();
    const ready = engine.initialize().then(async snapshot => {
        if (closing) return false;
        settings = await engine.getSettings();
        if (closing) return false;
        refreshTray(snapshot || await engine.status());
        return true;
    }).catch(async () => {
        if (!closing) {
            await diagnostics.record('startup_failed');
            dialog.showErrorBox(t('desktopNativeBootTitle'), t('desktopNativeBootError'));
            await dispose().catch(() => diagnostics.record('shutdown_failed'));
            app.exit(1);
        }
        return false;
    });
    if (!offline) openCloud().catch(() => fallback());
    return {window, engine, openCloud, dispose, serve, ready};
}
